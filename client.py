import base64
from typing import Literal, Optional
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext

import asyncio
import argparse
import logging

import fingerprint

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=9999)

args = parser.parse_args()

class Client:
    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        self._dh_param_generator: Literal[2, 5] = 2
        self._dh_param_key_size: int = 512
        self.public_key: Optional[dh.DHPublicKey] = None
        self.private_key: Optional[dh.DHPrivateKey] = None

        self.derived_key: Optional[bytes] = None
        self._public_fingerprint: Optional[fingerprint.Fingerprint] = None

        self._aes_key_size: Literal[128, 192, 256] = 256
        self.iv: Optional[bytes] = None
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
    
    async def start_client(self) -> None:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        logging.info(f"[CONNECTION] Connected to {self.host}:{self.port}")

        self.reader = reader
        self.writer = writer

        await self.handle_communication()

    async def handle_communication(self) -> None:
        await self.establish_secure_channel()

    async def establish_secure_channel(self) -> None: 
        serialized_parameters = await self.receive(self._dh_param_key_size)
        self.private_key, self.public_key = self.get_key_pair_from_serialized_parameters(serialized_parameters)
        
        logging.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.bubble_babble()}")

        shared_key = await self.handle_key_exchange()
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=self._aes_key_size // 8,
            info=None,
            salt=None,
        ).derive(shared_key)

        logging.info("[*] Waiting for other party to verify the hashed key")
        if await self.verify_derived_keys():
            logging.info(f"[ESTABLISHED SHARED KEY]")
        else:
            logging.critical("[!!CRITICAL!!] AN ADVERSARY IS LIKELY TRYING TO HIJACK YOUR COMMUNICATIONS.\n> PLEASE INVESTIGATE *IMMEDIATELY* <")
            exit(1)

        self.iv = await self.receive(16)

        self.initialize_cipher(self.derived_key, self.iv)
        logging.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")
  
    def initialize_cipher(self) -> None:
        if not self.derived_key and self.iv:
            raise ValueError("[!] Both a derived key and an IV is required to create a cipher")
            
        self.cipher = Cipher(algorithms.AES(self.derived_key), modes.GCM(self.iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def get_key_pair_from_serialized_parameters(
            self,
            serialized_parameters: bytes,
        ) -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
            """
            Takes serialized Diffie-Hellman parameters and generates a private and public key pair.

            Args:
                serialized_parameters (bytes): The serialized Diffie-Hellman parameters.

            Returns:
                tuple[dh.DHPrivateKey, dh.DHPublicKey]: A tuple containing the generated private and public keys.
            """
            parameters = serialization.load_pem_parameters(
                serialized_parameters, backend=default_backend()
            )
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            return private_key, public_key

    async def handle_key_exchange(self) -> bytes:
        """
        Handles the key exchange process.

        Args:
            private_key (dh.DHPrivateKey): The private key to use when getting the shared key
            public_key (dh.DHPublicKey): The public key to send to the server
        """
        server_public_key, _ = await asyncio.gather(
            self.receive(self._dh_param_key_size),
            self.send(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
        )
        logging.info("[KEY EXCHANGE] Exchanged public keys")

        # Authenticate party's public key fingerprint (SHA-256)
        self.perform_fingerprint_verification(server_public_key)

        server_public_key = serialization.load_pem_public_key(
            server_public_key, backend=default_backend()
        )
        
        shared_key = self.private_key.exchange(server_public_key)
        logging.info("[KEY EXCHANGE] Shared secret generated")

        return shared_key
        
    def perform_fingerprint_verification(self, public_key: bytes) -> None:
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        logging.info("[FINGERPRINT] Client's public key fingerprint verified")

    async def verify_derived_keys(self) -> bool:
        key_digest = self.calculate_hash(self.derived_key, hashes.SHA256())
        
        peer_key_digest, _ = await asyncio.gather(
            self.receive(32), # SHA256
            self.send(key_digest)
        )

        return key_digest == peer_key_digest
    
    def calculate_hash(self, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        digest = hashes.Hash(algorithm)
        digest.update(data)
        signature = digest.finalize()
        
        return signature

    def initialize_cipher(self, key: bytes, iv: bytes) -> None:
        self.cipher = Cipher(algorithms.AES(self.derived_key), modes.GCM(self.iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
    
    async def receive(self, buffer: int) -> bytes:
        data = await self.reader.read(buffer)
        if not data:
            logging.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    def pack_message(self, data: bytes) -> bytes:
        ciphertext = self.cipher_operation(data, self.encryptor)
        signature = self.sign_with_hmac(ciphertext, self.derived_key, hashes.SHA256())

        return ciphertext + signature

    def sign_with_hmac(self, data: bytes, key: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        hmac_digest = hmac.HMAC(key, algorithm)
        hmac_digest.update(data)
        signature = hmac_digest.finalize()

        return signature

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
    
if __name__ == "__main__":
    client = Client(args.host, args.port)
    try:
        asyncio.run(client.start_client())
    except KeyboardInterrupt:
        print("Received keyboard interrupt: exiting")