from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import fingerprint
import socket
import logging

logging.basicConfig(level=logging.INFO)


def generate_and_serialize_params() -> dict[dh.DHPrivateKey, dh.DHPublicKey, bytes]:
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    logging.info("[*] Generated key pair")

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
    }

def establish_connection(server: socket.socket) -> tuple:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 44454))
        logging.info("[*] Binded to address")

        server.listen(1)
        logging.info("[*] Listening for connection")

        conn, addr = server.accept()
        logging.info(f"[*] Got connection from {addr}")

        return conn, addr

def handle_key_exchange(peer_public_key: dh.DHPublicKey, private_key: dh.DHPrivateKey) -> bytes:
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key,
        backend=default_backend()
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

        peer_public_key = conn.recv(1024)
        logging.info("[*] Received client's public key")

        # Authenticate party's public key fingerprint (SHA-256)
        fingerprint.verify_public_key(conn, peer_public_key)

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
        logging.critical("[!!!] There is a **possibility** the channel was hijacked.\n(Please do not take this message too seriously)")
