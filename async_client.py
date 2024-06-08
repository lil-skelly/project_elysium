import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import asyncio
import argparse
import logging

import fingerprint

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=44454)

args = parser.parse_args()

class Client:
    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port

        self.reader = None
        self.writer = None

        self.public_key = None
        self.private_key = None

        self.derived_key = None
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
    
    async def start_client(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        logging.info(f"[CONNECTION] Connected to {self.host}:{self.port}")

        self.reader = reader
        self.writer = writer

        await self.handle_communication()

    async def handle_communication(self):
        serialized_parameters = await self.receive(512)
        self.private_key, self.public_key = self.get_key_pair_from_serialized_parameters(serialized_parameters)
        
        logging.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.bubble_babble()}")

        shared_key = await self.handle_key_exchange()
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=256,
            info=None,
            salt=None,
        ).derive(shared_key)

        logging.info(f"[ESTABLISHED SHARED KEY] {base64.b64encode(self.derived_key).decode()}")


    async def receive(self, buffer: int):
        data = await self.reader.read(buffer)
        if not data:
            logging.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

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
            self.receive(1024),
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
        
    def perform_fingerprint_verification(self, public_key: bytes):
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        logging.info("[FINGERPRINT] Client's public key fingerprint verified")

if __name__ == "__main__":
    client = Client(args.host, args.port)
    try:
        asyncio.run(client.start_client())
    except KeyboardInterrupt:
        print("Received keyboard interrupt: exiting")
