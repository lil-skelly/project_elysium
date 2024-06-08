import asyncio
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import fingerprint
import secrets
import base64
import logging

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=44454)

args = parser.parse_args()

class Server:
    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port

        self.reader = None
        self.writer = None

        self.public_key = None
        self.private_key = None
        self.serialized_parameters = None

        self.derived_key = None

        self.cipher = None
        self.encryptor = None
        self.decryptor = None
        self.iv = secrets.token_bytes(16)

        self._public_fingerprint: fingerprint.Fingerprint = None

    @property
    def public_fingerprint(self):
        if not self.public_key:
            return None
    
        self._public_fingerprint = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        self._public_fingerprint.key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return self._public_fingerprint
    
    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logging.info(f"[*] Serving at {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        try:
            self.reader = reader
            self.writer = writer
            client_ip, client_port = writer.get_extra_info('peername')
            logging.info(f"[CONNECTION] {client_ip}:{client_port}")

            self.generate_and_serialize_params()
            logging.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.bubble_babble()}")
            await self.send(self.serialized_parameters)
            logging.info("[*] Sent parameters to client")

            shared_key = await self.handle_key_exchange()
            self.derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=256,
                info=None,
                salt=None,
            ).derive(shared_key)

            self.cipher = Cipher(algorithms.AES(self.derived_key), modes.GCM(self.iv))
            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()
            
            
            # if self.verify_derived_keys():
            logging.info(f"[ESTABLISHED SHARED KEY] {base64.b64encode(self.derived_key).decode()}")


        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
                logging.info(f"Client connection from {client_ip}:{client_port} closed")
        

    async def receive(self, buffer: int):
        data = await self.reader.read(buffer)
        if not data:
            logging.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

    def generate_and_serialize_params(self) -> dict[dh.DHPrivateKey, dh.DHPublicKey, bytes]:
        """
        Generates a Diffie-Hellman key pair and serializes the parameters.

        This function generates a Diffie-Hellman key pair using a generator of 2 and a key size of 512 bits. 
        It then creates a SHA256 fingerprint of the public key and serializes the parameters in PEM format 
        using the PKCS3 parameter format.

        Returns:
            dict: A dictionary containing the private key, public key, serialized parameters.

        Raises:
            ValueError: If there is an issue with the key generation or serialization process.
        """
        parameters = dh.generate_parameters(
            generator=2, key_size=512, backend=default_backend()
        )
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        logging.info("[*] Generated key pair")
        
        self.serialized_parameters = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
        )
        logging.info("[*] Serialized parameters")
 
    async def handle_key_exchange(
        self
    ) -> bytes:
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

    def perform_fingerprint_verification(self, public_key: bytes):
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        logging.info("[FINGERPRINT] Client's public key fingerprint verified")

    async def verify_derived_keys(self): pass

    def encrypt(self, data: bytes) -> bytes:
        ciphertext = self.encryptor.update(data) + self.encryptor.finalize()
        return ciphertext
    
    def decrypt(self, data: bytes) -> bytes:
        plaintext = self.decryptor.update(data) + self.decryptor.finalize()
        return plaintext

if __name__ == "__main__":
    server = Server(args.host, args.port)
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("Received keyboard interrupt: exiting")

