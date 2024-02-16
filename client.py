import socket
import base64
import json
import argparse
from packet import Packet
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

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

# def h_make_packet(enc_session_key: bytes, nonce: bytes) -> str:
#     """
#     Creates a handshake packet.
#     This function takes the RSA public key and nonce, base64 encodes them, and then packs them into a JSON string.

#     Args:
#         key (bytes): The RSA public key.
#         nonce (bytes): The nonce.

#     Returns:
#         str: The JSON packet.
#     """
#     payload = {
#         "enc_session_key": base64.b64encode(enc_session_key).decode(),
#         "nonce": base64.b64encode(cipher_aes.nonce).decode(),
#     }
#     return json.dumps(payload)

# def make_message_packet(ciphertext: bytes, tag: bytes) -> str:
#     """
#     Creates a message packet.

#     Takes the ciphertext and tag, base64 encodes them, and then packs them into a JSON string.

#     Args:
#         ciphertext (bytes): The ciphertext.
#         tag (bytes): The ciphertexts' tag.

#     Returns:
#         str: The JSON packet.
#     """
#     payload = {
#         "ciphertext": base64.b64encode(ciphertext).decode(),
#         "tag": base64.b64encode(tag).decode()
#     }

#     return json.dumps(payload)

# def unpack_packet(packet: bytes) -> dict[bytes]:
#         """
#         Unpacks a message packet.

#         Decodes the JSON packet, then decodes the base64-encoded data, and returns the result as a dictionary.

#         Args:
#             packet (bytes): The JSON packet.

#         Returns:
#             dict[bytes]: The unpacked data.
#         """
#         payload = json.loads(packet)
#         data = {
#             "ciphertext": base64.b64decode(payload["ciphertext"]),
#             "tag": base64.b64decode(payload["tag"]),
#         }

#         return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(HOST_ADDR)
    print("Initiated connection with the server.")
    recipient_key = RSA.import_key(sock.recv(1024))
    print("[*] Received servers' RSA public key.")

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    packed_payload = Packet(enc_session_key=enc_session_key, nonce=cipher_aes.nonce).pack().encode()
    sock.sendall(packed_payload)
    data = sock.recv(1024) # Wait to get the end of handshake

    while True:
        message = str(input("[>] ")).encode()
        ciphertext, tag = encrypt(session_key, cipher_aes.nonce, message)
        packed_payload = Packet(ciphertext=ciphertext, tag=tag).pack().encode()
        sock.sendall(packed_payload)

        data = sock.recv(1024)
        unpacked_data = Packet(unpack_data=data.decode()).unpack()
        message = decrypt(session_key, cipher_aes.nonce, unpacked_data["ciphertext"], unpacked_data["tag"])
        print(message.decode())
