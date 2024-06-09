import asyncio
import argparse
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext

import fingerprint
import secrets
import base64
import logging
from typing import Literal, Optional

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=9999)

args = parser.parse_args()

class Server:
    def __init__(self, host: str, port: int) -> None:
        # Socket
        self.host: str = host
        self.port: int = port

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        # Diffie-Hellman
        self._dh_param_generator: Literal[2, 5] = 2
        self._dh_param_key_size: int = 512
        self.public_key: Optional[dh.DHPublicKey] = None
        self.private_key: Optional[dh.DHPrivateKey] = None

        self.derived_key: Optional[bytes] = None
        self._public_fingerprint: Optional[fingerprint.Fingerprint] = None

        # AES
        self._aes_key_size: Literal[128, 192, 256] = 256
        self.iv: bytes = secrets.token_bytes(16)
        self.cipher: Optional[Cipher] = None
        self.encryptor: Optional[CipherContext] = None
        self.decryptor: Optional[CipherContext] = None

    @property
    def public_fingerprint(self) -> fingerprint.Fingerprint | None:
        if self.public_key and not self._public_fingerprint: 
            self._public_fingerprint = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
            self._public_fingerprint.key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return self._public_fingerprint
    
        return None

    async def start_server(self) -> None:
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logging.info(f"[*] Serving at {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer) -> None:
        try:
            self.reader = reader
            self.writer = writer

            client_ip, client_port = writer.get_extra_info('peername')
            logging.info(f"[CONNECTION] {client_ip}:{client_port}")

            await self.establish_secure_channel()

        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
                logging.info(f"Client connection from {client_ip}:{client_port} closed")

    async def message_loop(self) -> None: ...

    async def establish_secure_channel(self) -> None:
        """Handles the establishment of a secure communication channel."""
        self.generate_and_serialize_params()
        logging.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.bubble_babble()}")
        
        await self.send(self.serialized_parameters)
        logging.debug("[*] Sent parameters to client")

        shared_key = await self.handle_key_exchange()
        
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=self._aes_key_size // 8,
            info=None,
            salt=None,
        ).derive(shared_key)

        logging.info("[*] Waiting for other party to verify the hashed key")
        if await self.verify_derived_keys():
            logging.info("[ESTABLISHED SHARED KEY]")
        else:
            logging.critical("[!!CRITICAL!!] AN ADVERSARY IS LIKELY TRYING TO HIJACK YOUR COMMUNICATIONS.\n> PLEASE INVESTIGATE *IMMEDIATELY* <")


        await self.send(self.iv)

        self.initialize_cipher(self.derived_key, self.iv)
        logging.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")

    def generate_and_serialize_params(self) -> None:
        """
        Generates a Diffie-Hellman key pair and serializes the parameters.

        This function generates a Diffie-Hellman key pair using a generator of 2 and a key size of 512 bits. 
        It then creates a SHA256 fingerprint of the public key and serializes the parameters in PEM format 
        using the PKCS3 parameter format.
        """
        parameters = dh.generate_parameters(
            generator=self._dh_param_generator, key_size=self._dh_param_key_size, backend=default_backend()
        )
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        print(len(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )))
        
        logging.info("[*] Generated key pair")
        
        self.serialized_parameters = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
        )
        logging.info("[*] Serialized parameters")
 
    async def handle_key_exchange(self) -> bytes:
        _, peer_public_key = await asyncio.gather(
            self.send(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )),
            self.receive(1024),
        )
        
        logging.info("[KEY EXCHANGE] Exchanged public keys")
        self.perform_fingerprint_verification(peer_public_key)

        peer_public_key = serialization.load_pem_public_key(
            peer_public_key, backend=default_backend()
        )
        shared_key = self.private_key.exchange(peer_public_key)
        logging.info("[KEY EXCHANGE] Shared secret generated")

        return shared_key

    def perform_fingerprint_verification(self, public_key: bytes) -> None:
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        logging.info("[FINGERPRINT] Client's public key fingerprint verified")

    async def verify_derived_keys(self) -> bool:
        key_digest = self.calculate_hash(self.derived_key, hashes.SHA256())
        
        _, peer_key_digest = await asyncio.gather(
            self.send(key_digest),
            self.receive(32) # SHA256
        )

        return key_digest == peer_key_digest

    def calculate_hash(self, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        digest = hashes.Hash(algorithm)
        digest.update(data)
        
        return digest.finalize()
  
    def initialize_cipher(self, key: bytes, iv: bytes) -> None:
        self.cipher = Cipher(algorithms.AES(self.derived_key), modes.GCM(self.iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def cipher_operation(self, data: bytes, cryptor: CipherContext) -> bytes:
        """Encrypts/decrypts data using the provided cryptor (CipherContext) object.

        Parameters
        ----------
        data : bytes
            Data to be encrypted/decrypted
        cryptor : CipherContext
            The CipherContext representing the encryptor/decryptor

        Returns
        -------
        bytes
            Result of the according cryptographic operation
        """
        result = cryptor.update(data) + cryptor.finalize()
        return result
    
    def pack_message(self, data: bytes) -> bytes:
        ciphertext = self.cipher_operation(data, self.encryptor)
        signature = self.sign_with_hmac(ciphertext, self.derived_key, hashes.SHA256())

        return ciphertext + signature

    def sign_with_hmac(self, data: bytes, key: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        hmac_digest = hmac.HMAC(key, algorithm)
        hmac_digest.update(data)
        signature = hmac_digest.finalize()

        return signature

    async def receive(self, buffer: int) -> bytes:
        data = await self.reader.read(buffer)
        if not data:
            logging.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

def main(args) -> None:
    server = Server(args.host, args.port)
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("Received keyboard interrupt: exiting")

if __name__ == "__main__":
    main(args)