import base64
from typing import Literal, Optional
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext

import utils
import asyncio
import argparse
import logging

logger = logging.getLogger("client")
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=9999)

args = parser.parse_args()

class Client(utils.BaseSecureAsynchronousSocket):
    def __init__(self, host: str, port: int, logger: logging.Logger) -> None:
        super().__init__(host, port, logger)

    async def start_socket(self) -> None:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info(f"[CONNECTION] Connected to {self.host}:{self.port}")

        self.reader = reader
        self.writer = writer

        await self.handle_communication()

    async def handle_communication(self) -> None:
        await self.establish_secure_channel()

    async def establish_secure_channel(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        
        self.logger.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.bubble_babble()}")

        shared_key = await self.handle_key_exchange()
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=self._aes_key_size // 8,
            info=None,
            salt=None,
        ).derive(shared_key)

        self.logger.info("[*] Waiting for other party to verify the hashed key")
        if await self.verify_derived_keys():
            self.logger.info(f"[ESTABLISHED SHARED KEY]")
        else:
            self.logger.critical("[!!CRITICAL!!] AN ADVERSARY IS LIKELY TRYING TO HIJACK YOUR COMMUNICATIONS.\n> PLEASE INVESTIGATE *IMMEDIATELY* <")
            exit(1)

        self.iv = await self.receive(16)

        self.initialize_cipher()
        self.logger.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")
  
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
        self.logger.debug("[KEY EXCHANGE] Exchanged public keys")

        # Authenticate party's public key fingerprint (SHA-256)
        self.perform_fingerprint_verification(server_public_key)

        server_public_key = serialization.load_pem_public_key(
            server_public_key, backend=default_backend()
        )
        
        shared_key = self.private_key.exchange(ec.ECDH(), server_public_key)
        self.logger.debug("[KEY EXCHANGE] Shared secret generated")

        return shared_key
        
  
    
if __name__ == "__main__":
    client = Client(args.host, args.port, logger)
    try:
        asyncio.run(client.start_socket())
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt: exiting")