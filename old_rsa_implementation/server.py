import argparse
import socketserver
import json
import base64
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
    help="Host IP to use when serving"
)
parser.add_argument(
    "-p",
    "--port",
    required=True,
    type=int,
    help="Port to use when hosting the server"
)
args = parser.parse_args()

HOST_ADDR = (args.host, args.port)

key = RSA.generate(2048)
public_key = key.public_key().export_key()
session_key = get_random_bytes(16)


class TCPHandler(socketserver.BaseRequestHandler):
    cipher_rsa = PKCS1_OAEP.new(key)
    def recv(self, bufsize: int) -> str:
        """
        Receives data from a client connection.
        Simple wrapper around the socket's recv method.

        Args:
            bufsize (int): The number of bytes to receive.

        Returns:
            str: The (decoded) received data.
        """
        data = self.request.recv(bufsize).decode()
        return data

    def send(self, data: bytes) -> None:
        """
        Sends data to a client connection.

        Simple wrapper around the socket's `sendall` method.

        Args:
            data (bytes): The data to send.
        """
        self.request.sendall(data)

    def encrypt(
        self, session_key: bytes, nonce: bytes, data: bytes
    ) -> tuple[bytes, bytes]:
        """
        Encrypts a message.

        Creates an AES cipher using the provided session key and nonce, 
        and then uses this cipher to encrypt and digest the data.

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

    def decrypt(
        self, session_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes
    ) -> bytes:
        """
        Decrypts a message.

        Creates an AES cipher using the provided session key and nonce, and then uses this cipher to decrypt and verify the data.

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

    def handle(self) -> None:
        """
        Handles a client connection.

        Performs the initial handshake with the client, establishing a secure AES session using assymetric encryption (RSA).
        It then enters a loop where it continuously receives encrypted messages from the client, decrypts them, and sends back encrypted responses.
        """
        print("[*] Received connection from: ", self.client_address[0])
        self.send(public_key)
        print("[*] Sent RSA public key")

        packet = self.recv(1024)
        data = Packet(unpack_data=packet).unpack()
        session_key, nonce = self.cipher_rsa.decrypt(data["enc_session_key"]), data["nonce"]
        print("[*] Decrypted session key and nonce. Creating cipher . . .")

        # Create matching AES cipher with the AES session key and nonce
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        print("[EOH] Secure communication channel established.")
        self.send(b"OP_EOH")

        while True:
            unpacked_data = Packet(unpack_data=self.recv(1024)).unpack()
            message = self.decrypt(
                session_key, nonce, unpacked_data["ciphertext"], unpacked_data["tag"]
            )
            print(message.decode())

            message = str(input("[>] "))

            ciphertext, tag = self.encrypt(session_key, nonce, message.encode())
            packed_payload = Packet(ciphertext=ciphertext, tag=tag).pack()
            self.send(packed_payload.encode())


with socketserver.TCPServer(HOST_ADDR, TCPHandler) as server:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[>w<] Received keyboard interrupt. Exiting.")
