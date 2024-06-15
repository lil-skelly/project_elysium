import asyncio
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import secrets
import logging

import utils

logger = logging.getLogger("client")
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="127.0.0.1")
parser.add_argument("--port", type=int, default=9999)

args = parser.parse_args()


class Server(utils.BaseSecureAsynchronousSocket):
    def __init__(self, host: str, port: int, logger: logging.Logger) -> None:
        super().__init__(host, port, logger)
        self.iv = secrets.token_bytes(16)

    async def start_socket(self) -> None:
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.logger.info(f"[*] Serving at {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def _exchange_iv(self) -> None:
        await self.send(self.iv)

    async def handle_client(self, reader, writer) -> None:
        try:
            self.reader = reader
            self.writer = writer

            client_ip, client_port = writer.get_extra_info("peername")
            self.logger.info(f"[CONNECTION] {client_ip}:{client_port}")

            await self.establish_secure_channel()

        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
                self.logger.info(f"Client connection from {client_ip}:{client_port} closed")


def main(args) -> None:
    server = Server(args.host, args.port, logger)
    try:
        asyncio.run(server.start_socket())
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt: exiting")


if __name__ == "__main__":
    main(args)
