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

    async def establish_secure_channel(self) -> None:
        """Handles the establishment of a secure communication channel."""
        self.generate_and_serialize_key()
        self.logger.info(
            f"[*] Your public key's fingerprint: {self.public_fingerprint.get_bubble_babble()}"
        )

        await self.get_key()

        await self.establish_key()
        
        await self.send(self.iv)

        self.initialize_cipher()
        self.logger.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")

    def generate_and_serialize_key(self) -> None:
        """
        Generates a Diffie-Hellman key pair and serializes the parameters.

        This function generates a Diffie-Hellman key pair using a generator of 2 and a key size of 512 bits.
        It then creates a SHA256 fingerprint of the public key and serializes the parameters in PEM format
        using the PKCS3 parameter format.
        """

        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()

        self.logger.debug("[*] Generated key pair & serialized public key")

   

def main(args) -> None:
    server = Server(args.host, args.port, logger)
    try:
        asyncio.run(server.start_socket())
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt: exiting")


if __name__ == "__main__":
    main(args)
