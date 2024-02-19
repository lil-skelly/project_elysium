from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import fingerprint
import socket
import logging
import argparse

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, required=False, default="127.0.0.1")
parser.add_argument("--port", type=int, required=False, default=44454)
args = parser.parse_args()


def generate_and_serialize_params() -> dict[dh.DHPrivateKey, dh.DHPublicKey, bytes]:
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
    logging.info(f"[*] Your public key's fingerprint:\n{p_fingerprint.fingerprint}")

    serialized_parameters = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )
    logging.info("[*] Serialized parameters")
    conn.sendall(serialized_parameters)
    logging.info("[*] Sent parameters to peer")

    return {
        "private_key": private_key,
        "public_key": public_key,
        "serialized_params": serialized_parameters,
        "fingerprint": p_fingerprint
    }


def establish_connection(server: socket.socket) -> tuple:
    """
    Establishes a connection with a client using the provided server socket.

    This function sets the SO_REUSEADDR socket option to allow the reuse of local addresses. 
    It then binds the server to the specified host and port, and starts listening for an incoming connection. 
    Once a connection is established, it accepts the connection and returns the connection object and the client's address.

    Args:
        server (socket.socket): The server socket to use to establish the connection.

    Returns:
        tuple: A tuple containing the connection socket and the client's address.
    """
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    logging.info("[*] Binded to address")

    server.listen(1)
    logging.info("[*] Listening for connection")

    conn, addr = server.accept()
    logging.info(f"[*] Got connection from {addr}")

    return conn, addr


def handle_key_exchange(
    peer_public_key: dh.DHPublicKey, private_key: dh.DHPrivateKey
) -> bytes:
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key, backend=default_backend()
    )
    conn.sendall(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    logging.info("[*] Sent public key to peer")
    shared_key = private_key.exchange(peer_public_key)

    return shared_key


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    try:
        conn, addr = establish_connection(server)

        dh_data = generate_and_serialize_params()
        private_key = dh_data["private_key"]
        public_key = dh_data["public_key"]
        p_fingerprint = dh_data["fingerprint"]

        peer_public_key = conn.recv(1024)
        logging.info("[*] Received client's public key")

        # Authenticate party's public key fingerprint (SHA-256)
        p_fingerprint.key = peer_public_key
        p_fingerprint.verify_fingerprint()

        shared_key = handle_key_exchange(peer_public_key, private_key)
        logging.info("[*] Succesfull key exchange")

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=None,
            salt=None,
        ).derive(shared_key)

    except KeyboardInterrupt:
        logging.error("[>w<] Received keyboard interrupt. Exiting")
    except socket.error as e:
        logging.error(f"[>w<] {e}")
        logging.critical(
            "[!!!] There is a **possibility** the channel was hijacked.\n(Please do not take this message too seriously)"
        )
