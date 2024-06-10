
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
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
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        self.logger.info(f"[*] Your public key's fingerprint: {self.public_fingerprint.get_bubble_babble()}")

        await self.get_key()

        await self.establish_key()

        self.iv = await self.receive(16)

        self.initialize_cipher()
        self.logger.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")


if __name__ == "__main__":
    client = Client(args.host, args.port, logger)
    try:
        asyncio.run(client.start_socket())
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt: exiting")