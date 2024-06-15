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

class CryptographicUtilities:
    def __init__(self) -> None:
        self._aes_key_size: Literal[128, 192, 256] = 256
        self.iv: Optional[bytes] = None

        self.cipher: Optional[Cipher] = None
        self.encryptor: Optional[CipherContext] = None
        self.decryptor: Optional[CipherContext] = None

    def initialize_cipher(self, key: bytes, iv: bytes) -> None:
        self.cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def pack_message(self, data: bytes) -> bytes:
        ciphertext = self.cipher_operation(data, self.encryptor)
        signature = self.sign_with_hmac(ciphertext, self.derived_key, hashes.SHA256())

        return ciphertext + signature

    def sign_with_hmac(self, data: bytes, key: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
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
        digest = hashes.Hash(algorithm)
        digest.update(data)
        signature = digest.finalize()
        
        return signature


class BaseAsynchronousSocket(ABC):
    def __init__(self, host: str, port: str, logger: logging.Logger) -> None:
        self.host = host
        self.port = port
        self.logger = logger

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    @abstractmethod
    async def start_socket(self) -> None: ...

    async def receive(self, buffer: int) -> bytes:
        data = await self.reader.read(buffer)
        if not data:
            self.logger.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()


class BaseSecureAsynchronousSocket(BaseAsynchronousSocket, CryptographicUtilities):
    """
    Abstract class representing the base for an asynchronous socket with cryptographic utilities.
    Gathers common cryptographic functionality found in both the server and the client and provides an outline
    on how they should operate.
    """
    def __init__(self, host: str, port: str, logger: logging.Logger) -> None:
        super().__init__(host, port, logger)
        CryptographicUtilities.__init__(self)


        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None

        self.derived_key: Optional[bytes] = None
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

        self.initialize_cipher(self.derived_key, self.iv)
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
        key_digest = self.calculate_hash(self.derived_key, hashes.SHA256())

        _, peer_key_digest = await asyncio.gather(
            self.send(key_digest), self.receive(32)  # SHA256
        )

        return key_digest == peer_key_digest

    async def get_derived_key(self) -> None:
        shared_key = await self.handle_key_exchange()

        self.derived_key = HKDF(
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
        response = input(prompt).lower()
        if response in {"y", "n"}:
            return response == "y"
        else:
            print("[>w<] Invalid input. Enter 'y' or 'n'.")