import argparse
import socketserver
import json
import base64
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
    def recv(self, bufsize: int) -> str:
        """
        Receives data from a client connection.
        Simple wrapper around the socket's recv method.

        Args:
            bufsize (int): The number of bytes to receive.

        Returns:
            str: The (decoded) received data.
        """
        data = self.request.recv(size).decode()
        return data

    def send(self, data: bytes) -> None:
        """
        Sends data to a client connection.

        Simple wrapper around the socket's `sendall` method.

        Args:
            data (bytes): The data to send.
        """
        self.request.sendall(data)

    def h_unpack_packet(self, packet: bytes) -> dict[bytes]:
        """
        Unpacks a handshake packet.

        Decodes the JSON packet, then decodes the base64-encoded data, and returns the result as a dictionary.

        Args:
            packet (str): The JSON packet.

        Returns:
            dict[bytes]: The unpacked data.
        """
        payload = json.loads(packet)
        data = {
            "enc_session_key": base64.b64decode(payload["enc_session_key"]),
            "nonce": base64.b64decode(payload["nonce"]),
        }

        return data

    def unpack_packet(self, packet: bytes) -> dict[bytes]:
        """
        Unpacks a message packet.

        Decodes the JSON packet, then decodes the base64-encoded data, and returns the result as a dictionary.

        Args:
            packet (bytes): The JSON packet.

        Returns:
            dict[bytes]: The unpacked data.
        """
        payload = json.loads(packet)
        data = {
            "ciphertext": base64.b64decode(payload["ciphertext"]),
            "tag": base64.b64decode(payload["tag"]),
        }

        return data

    def make_message_packet(self, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Creates a message packet.

        Takes the ciphertext and tag, base64 encodes them, and then packs them into a JSON string.

        Args:
            ciphertext (bytes): The ciphertext.
            tag (bytes): The tag.

        Returns:
            bytes: The JSON packet.
        """
        payload = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

        return json.dumps(payload)

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
        cipher_rsa = PKCS1_OAEP.new(key)

        self.send(public_key)  # END OF KEY EXCHANGE
        print("[*] Sent RSA public key")

        packet = self.recv(1024)
        data = self.h_unpack_packet(packet)
        session_key, nonce = cipher_rsa.decrypt(data["enc_session_key"]), data["nonce"]
        print("[*] Decrypted session key and nonce. Creating cipher . . .")

        # Create matching AES cipher with the AES session key and nonce
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        print("[EOH] Secure communication channel established.")
        self.send(b"OP_EOH")

        while True:
            unpacked_data = self.unpack_packet(self.recv(1024))
            message = self.decrypt(
                session_key, nonce, unpacked_data["ciphertext"], unpacked_data["tag"]
            )
            print(message.decode())

            message = str(input("[>] "))

            ciphertext, tag = self.encrypt(session_key, nonce, message.encode())
            packed_payload = self.make_message_packet(ciphertext, tag)
            self.send(packed_payload.encode())


with socketserver.TCPServer(HOST_ADDR, TCPHandler) as server:
    try:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
    except KeyboardInterrupt:
        print("[>w<] Received keyboard interrupt. Exiting.")
