import socket
import base64
import json
import argparse
from packet import Packet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


parser = argparse.ArgumentParser()
parser.add_argument(
    "-H",
    "--host",
    type=str,
    required=True,
    help="Server IP to connect to"
)
parser.add_argument(
    "-p",
    "--port",
    required=True,
    type=int,
    help="Port to use when connecting to the server"
)
args = parser.parse_args()
# TODO: Validate the IP address

HOST_ADDR = (args.host, args.port)

key = RSA.generate(2048)
session_key = get_random_bytes(16)

def encrypt(session_key: bytes, nonce: bytes, data: bytes) -> tuple[bytes]:
    """
    Encrypts a message.

    Creates an AES cipher using the provided session key and nonce, 
    and then proceeds to encrypt and digest the data.

    Args:
        key (bytes): The session key.
        nonce (bytes): The nonce.
        data (bytes): The data to encrypt.

    Returns:
        tuple[bytes]: The ciphertext and tag.
    """
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return ciphertext, tag

def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    """
    Decrypts a message.

    Creates an AES cipher using the provided session key and nonce, 
    and then proceeds to decrypt and verify the data.

    Args:
        key (bytes): The session key.
        nonce (bytes): The nonce.
        ciphertext (bytes): The ciphertext.
        tag (bytes): The tag.

    Returns:
        str: The decrypted message.
    """
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return message

def handle_rsa_key(sock: socket.socket) -> tuple[bytes]:
    """
    Receives the server's RSA public key and encrypts the session key with it.

    Args:
        sock (socket.socket): The socket object.
    
    Returns:
        tuple[bytes]: The recipient's public key, the rsa cipher and the encrypted session key.
    """
    try:
        recipient_key = RSA.import_key(sock.recv(1024))
        print("[*] Received servers' RSA public key.")

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        return recipient_key, cipher_rsa, enc_session_key
    except socket.error as e:
        print(f"[>w<] Error: Could not receive the server's RSA public key. {e}")
        sock.close()
        exit(1)
    
def handle_handshake(sock: socket.socket, enc_session_key, nonce) -> None:
    try:
        packed_payload = Packet(enc_session_key=enc_session_key, nonce=nonce).pack().encode()
        sock.sendall(packed_payload)
        data = sock.recv(1024) # Wait to get the end of handshake
        print("[*] Handshake completed.")
    except socket.error as e:
        print(f"[>w<] Error: Could not send the encrypted session key. {e}")
        sock.close()
        exit(1)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    sock.connect(HOST_ADDR)
    print("Initiated connection with the server.")
    # Receive the server's RSA public key and encrypt the session key with it
    recipient_key, cipher_rsa, enc_session_key = handle_rsa_key(sock)
    # Generate and send the handshake packet
    handle_handshake(sock, enc_session_key, cipher_aes.nonce)

    while True:
        message = str(input("[>] ")).encode()
        ciphertext, tag = encrypt(session_key, cipher_aes.nonce, message)
        packed_payload = Packet(ciphertext=ciphertext, tag=tag).pack().encode()
        sock.sendall(packed_payload)

        data = sock.recv(1024)
        unpacked_data = Packet(unpack_data=data.decode()).unpack()
        message = decrypt(session_key, cipher_aes.nonce, unpacked_data["ciphertext"], unpacked_data["tag"])
        print(message.decode())
