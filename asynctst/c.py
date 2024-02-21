from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from ...project_elysium import fingerprint
import base64
import logging
import asyncio
import argparse

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, required=False, default="127.0.0.1")
parser.add_argument("--port", type=int, required=False, default=44454)

args = parser.parse_args()


def handle_serialized_params(
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
    p_fingerprint = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
    p_fingerprint.key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logging.info(f"[*] Your public key's fingerprint:\n{p_fingerprint.bubble_babble()}")
    return private_key, public_key


async def handle_key_exchange(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    private_key: dh.DHPrivateKey,
    public_key: dh.DHPublicKey,
) -> bytes:
    """
    Handles the key exchange process.

    Args:
        client (socket.socket): Client socket
        private_key (dh.DHPrivateKey): The private key to use when getting the shared key
        public_key (dh.DHPublicKey): The public key to send to the server
    """
    writer.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    await writer.drain()
    logging.info("[*] Sent public key to server")

    server_public_key = await reader.read(1024)
    print(server_public_key.decode())
    logging.info("[*] Received server's public key")

    # Authenticate party's public key fingerprint (SHA-256)
    fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
    fingerprint_.key = server_public_key
    fingerprint_.verify_fingerprint()

    server_public_key = serialization.load_pem_public_key(
        server_public_key, backend=default_backend()
    )
    shared_key = private_key.exchange(server_public_key)

    return shared_key


async def main():
    try:
        reader, writer = await asyncio.open_connection(host=args.host, port=args.port)
        logging.info("[*] Connected to server")

        serialized_parameters = await reader.read(1024)
        print(serialized_parameters)
        logging.info("[*] Received DH parameters")

        private_key, public_key = handle_serialized_params(serialized_parameters)
        logging.info("[*] Loaded parameters and generated key pair")

        shared_key = await handle_key_exchange(reader, writer, private_key, public_key)
        logging.info("[*] Successfull exchange")

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=None,
            salt=None,
        ).derive(shared_key)

        writer.close()
        await writer.wait_closed()

    # except socket.error as e:
    #     logging.error(f"[>w<] {e}")
    except ConnectionRefusedError:
        logging.error("[>w<] Connection refused. Exiting")
        exit(1)


asyncio.run(main())
