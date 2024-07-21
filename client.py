
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

class Client(utils.BaseSecureAsynSock):
    def __init__(self, host: str, port: int, logger: logging.Logger) -> None:
        super().__init__(host, port, logger)

    async def start_socket(self) -> None:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        self.logger.info(f"[CONNECTION] Connected to {self.host}:{self.port}")

        self.reader = reader
        self.writer = writer

        await self.handle_communication()

        msg = self.pack_message(b"hey i am good gay guy")
        print(msg)
        decrypted_msg = self.unpack_message(msg)
        print(decrypted_msg)
    async def _exchange_iv(self) -> None:
        self._iv = await self.receive(16)

    async def handle_communication(self) -> None:
        await self.establish_secure_channel()


if __name__ == "__main__":
    client = Client(args.host, args.port, logger)
    try:
        asyncio.run(client.start_socket())
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt: exiting")