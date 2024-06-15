from abc import ABC, abstractmethod
from typing import Optional, Literal
import asyncio

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    CipherContext,
)

import fingerprint
import logging

class CryptoUtils(ABC):
    def __init__(self) -> None:
        """
        Attributes
        ----------
        _aes_key_size : Literal[128, 192, 256]
            Size of the AES key in bits (default is 256).
        _iv : Optional[bytes]
            Initialization vector for AES-GCM mode.
        _key : Optional[bytes]
            AES key used for encryption/decryption.
        _cipher : Optional[Cipher]
            Cipher object for cryptographic operations.
        _encryptor : Optional[CipherContext]
            Encryptor context for AES encryption.
        _decryptor : Optional[CipherContext]
            Decryptor context for AES decryption.
        """
        self._aes_key_size: Literal[128, 192, 256] = 256
        self._iv: Optional[bytes] = None
        self._key: Optional[bytes] = None

        self.cipher: Optional[Cipher] = None
        self._encryptor: Optional[CipherContext] = None
        self._decryptor: Optional[CipherContext] = None

    def initialize_cipher(self, key: bytes, iv: bytes) -> None:
        """
        Initialize the encryptor and decryptor contexts for future data encryption/decryption

        Parameters
        ----------
        key : bytes
            AES key
        iv : bytes
            Initialization vector
        """
        self._cipher = Cipher(algorithms.AES(self._key), modes.GCM(self._iv))
        self._encryptor = self._cipher.encryptor()
        self._decryptor = self._cipher.decryptor()

    def pack_message(self, data: bytes) -> bytes:
        """
        Pack data for transmission by encrypting and signing it.

        Parameters
        ----------
        data : bytes
            Data to be packed.

        Returns
        -------
        bytes
            Encrypted data with appended HMAC signature.
        """
        ciphertext = self.cipher_operation(data, self.encryptor)
        signature = self.sign_with_hmac(ciphertext, self._key, hashes.SHA256())

        return ciphertext + signature

    def sign_with_hmac(self, data: bytes, key: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        """
        Sign `data` using HMAC with the given `key` and hash `algorithm`

        Parameters
        ----------
        data : bytes
            Data to sign
        key : bytes
            Key to sign data with
        algorithm : hashes.HashAlgorithm
            Hashing algorithm to use

        Returns
        -------
        bytes
            Signature of the data
        """
        hmac_digest = hmac.HMAC(key, algorithm)
        hmac_digest.update(data)
        signature = hmac_digest.finalize()

        return signature
        
    def cipher_operation(self, data: bytes, cryptor: CipherContext) -> bytes:
        """Encrypts/decrypts data using the provided cryptor (CipherContext) object.

        Parameters
        ----------
        data : bytes
            Data to be encrypted/decrypted
        cryptor : CipherContext
            The CipherContext representing the encryptor/decryptor

        Returns
        -------
        bytes
            Result of the according cryptographic operation
        """
        result = cryptor.update(data) + cryptor.finalize()
        return result
    
    def calculate_hash(self, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        """
        Calculate the hash of the given data using the specified hashing algorithm.

        Parameters
        ----------
        data : bytes
            Data to hash.
        algorithm : hashes.HashAlgorithm
            Hashing algorithm to use.

        Returns
        -------
        bytes
            Hash value of the data.
        """
        digest = hashes.Hash(algorithm)
        digest.update(data)
        signature = digest.finalize()
        
        return signature


class BaseAsyncSock(ABC):
    """
    Base class for an asynchronous socket.

    This abstract base class provides a framework for establishing and managing
    an asynchronous socket connection. It includes methods for starting the socket,
    sending data, and receiving data. Derived classes should implement the 
    `start_socket` method to handle the specifics of establishing the connection.
    """
    def __init__(self, host: str, port: str, logger: logging.Logger) -> None:
        """    
        Parameters
        ----------
        host : str
            The hostname or IP address of the socket server.
        port : str
            The port number of the socket server.
        logger : logging.Logger
            Logger instance for logging socket events.

        Attributes:
        -----------
        host (str): The hostname or IP address of the socket server.
        port (str): The port number of the socket server.
        logger (logging.Logger): Logger instance for logging socket events.
        reader (Optional[asyncio.StreamReader]): Asynchronous stream reader for the socket.
        writer (Optional[asyncio.StreamWriter]): Asynchronous stream writer for the socket.

        """
        self.host = host
        self.port = port
        self.logger = logger

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    @abstractmethod
    async def start_socket(self) -> None: ...
    """Abstract method to start the socket connection. Must be implemented by derived classes."""

    async def receive(self, buffer: int) -> bytes:
        """
        Asynchronously receives data from the socket.
        
        Parameters
        ----------
        buffer : int
            The maximum number of bytes to read.
            
        Returns
        -------
        bytes
            The data received from the socket.
        
        Logs a warning if no data is received.
        """
        data = await self.reader.read(buffer)
        if not data:
            self.logger.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes) -> None:
        """
        Asynchronously sends data through the socket.
        
        Parameters
        ----------
        data : bytes
            The data to be sent.
        """
        self.writer.write(data)
        await self.writer.drain()


class BaseSecureAsynSock(BaseAsyncSock, CryptoUtils):
    """
    Abstract class representing the base for an asynchronous socket with cryptographic utilities.
    Gathers common cryptographic functionality found in both the server and the client and provides an outline
    on how they should operate.
    """
    def __init__(self, host: str, port: str, logger: logging.Logger) -> None:
        super().__init__(host, port, logger)
        CryptoUtils.__init__(self)


        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None

        self._public_fingerprint: Optional[fingerprint.Fingerprint] = None

    @property
    def public_fingerprint(self) -> Optional[fingerprint.Fingerprint]:
        if self.public_key and not self._public_fingerprint: 
            self._public_fingerprint = fingerprint.Fingerprint(hashes.SHA256())
            self._public_fingerprint.key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return self._public_fingerprint
    
        return None
    
    @abstractmethod
    async def _exchange_iv(self) -> None: ...

    def generate_key_pair(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.logger.debug("[*] Generated key pair & serialized public key")

    async def establish_secure_channel(self) -> None:
        """Handles the establishment of a secure communication channel."""
        self.generate_key_pair()

        self.logger.info(
            f"[*] Your public key's fingerprint: {self.public_fingerprint.get_bubble_babble()}"
        )

        await self.get_derived_key()

        await self.handle_key_verification()
        
        await self._exchange_iv()

        self.initialize_cipher(self._key, self._iv)
        self.logger.info("[ESTABLISHED SECURE COMMUNICATION CHANNEL]")

    async def handle_key_exchange(self) -> bytes:
        serialized_public_key = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _, peer_public_key = await asyncio.gather(
            self.send(
                serialized_public_key
            ),
            self.receive(1024),
        )

        self.logger.info("[KEY EXCHANGE] Exchanged public keys")
        self.perform_fingerprint_verification(peer_public_key)

        peer_public_key = serialization.load_pem_public_key(
            peer_public_key
        )
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.logger.info("[KEY EXCHANGE] Shared secret generated")

        return shared_key
    
    def perform_fingerprint_verification(self, public_key: bytes) -> None:
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        self.logger.info("[FINGERPRINT] Public key fingerprint verified")

    async def handle_key_verification(self) -> None:
        self.logger.debug("[*] Waiting for other party to verify the hashed key")
        if await self.verify_key_exchange():
            self.logger.info("[ESTABLISHED SHARED KEY]")
        else:
            logging.critical(
                "[!!CRITICAL!!] AN ADVERSARY IS LIKELY TRYING TO HIJACK YOUR COMMUNICATIONS.\n> PLEASE INVESTIGATE *IMMEDIATELY* <"
            )
            exit(1)

    async def verify_key_exchange(self) -> bool:
        key_digest = self.calculate_hash(self._key, hashes.SHA256())

        _, peer_key_digest = await asyncio.gather(
            self.send(key_digest), self.receive(32)  # SHA256
        )

        return key_digest == peer_key_digest

    async def get_derived_key(self) -> None:
        shared_key = await self.handle_key_exchange()

        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=self._aes_key_size // 8,
            info=None,
            salt=None,
        ).derive(shared_key)


def get_user_confirmation(prompt: str) -> bool:
    """Prompt the user with a yes/no question using the given prompt

    Parameters
    ----------
    prompt : str
        Prompt to present the user

    Returns
    -------
    bool
        Returns True if users answers "y", otherwise returns False
    """
    while True:
        response = input(prompt).lower().strip()
        if response in {"y", "n"}:
            return response == "y"
        else:
            print("[>w<] Invalid input. Enter 'y' or 'n'.")