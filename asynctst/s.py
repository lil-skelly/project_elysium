from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import fingerprint
import asyncio
import logging
import argparse

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, required=False, default="127.0.0.1")
parser.add_argument("--port", type=int, required=False, default=44454)
args = parser.parse_args()


async def generate_and_serialize_params() -> dict[dh.DHPrivateKey, dh.DHPublicKey, bytes]:
    """
    Generates a Diffie-Hellman key pair and serializes the parameters.

    This function generates a Diffie-Hellman key pair using a generator of 2 and a key size of 512 bits. 
    It then creates a SHA256 fingerprint of the public key and serializes the parameters in PEM format 
    using the PKCS3 parameter format. The serialized parameters are sent to the peer.

    Returns:
        dict: A dictionary containing the private key, public key, serialized parameters, and the fingerprint object.

    Raises:
        ValueError: If there is an issue with the key generation or serialization process.
    """
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    logging.info("[*] Generated key pair")

    p_fingerprint = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
    p_fingerprint.key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logging.info(f"[*] Your public key's fingerprint:\n{p_fingerprint.bubble_babble()}")

    serialized_parameters = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )
    logging.info("[*] Serialized parameters")

    return {
        "private_key": private_key,
        "public_key": public_key,
        "serialized_params": serialized_parameters,
        "fingerprint": p_fingerprint
    }


async def handle_key_exchange(
    writer,
    peer_public_key: dh.DHPublicKey,
    public_key: dh.DHPublicKey,
    private_key: dh.DHPrivateKey
) -> bytes:
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key, backend=default_backend()
    )
    writer.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    await writer.drain()
    logging.info("[*] Sent public key to peer")
    shared_key = private_key.exchange(peer_public_key)

    return shared_key

async def handler(reader, writer):
    try:

        dh_data = await generate_and_serialize_params()
        private_key = dh_data["private_key"]
        public_key = dh_data["public_key"]
        p_fingerprint = dh_data["fingerprint"]
        serialized_parameters = dh_data["serialized_params"]

        writer.write(serialized_parameters)
        await writer.drain()
        logging.info("[*] Sent parameters to peer")


        peer_public_key = await reader.read(1024)
        logging.info("[*] Received client's public key")

        # Authenticate party's public key fingerprint (SHA-256)
        p_fingerprint.key = peer_public_key
        p_fingerprint.verify_fingerprint()

        shared_key = await handle_key_exchange(writer, peer_public_key, public_key, private_key)
        logging.info("[*] Keys match. Succesfull key exchange.")


        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=None,
            salt=None,
        ).derive(shared_key)
        writer.close()
        await writer.wait_closed()

    except KeyboardInterrupt:
        logging.error("[>w<] Received keyboard interrupt. Exiting")
        writer.close()
        await writer.wait_closed()
        exit(1)

async def main():
    server = await asyncio.start_server(
        main,
        args.host,
        args.port
    )
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logging.info(f'[*] Serving on {addrs}')
    async with server:
        await server.serve_forever()
asyncio.run(main())