from abc import ABC, abstractmethod
from typing import Optional, Literal
import asyncio

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    CipherContext,
)

import fingerprint
import logging

class BaseSecureAsynchronousSocket(ABC):
    """
    Abstract class representing the base for an asynchronous socket with cryptographic utilities.
    Gathers common cryptographic functionality found in both the server and the client and provides an outline
    on how they should operate.
    """
    def __init__(self, host: str, port: str, logger: logging.Logger) -> None:
        self.host = host
        self.port = port
        self.logger = logger

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        self.derived_key: Optional[bytes] = None
        self._public_fingerprint: Optional[fingerprint.Fingerprint] = None

        self._aes_key_size: Literal[128, 192, 256] = 256
        self.iv: Optional[bytes] = None

        self.cipher: Optional[Cipher] = None
        self.encryptor: Optional[CipherContext] = None
        self.decryptor: Optional[CipherContext] = None

        self._public_fingerprint: Optional[fingerprint.Fingerprint] = None

    @property
    def public_fingerprint(self) -> Optional[fingerprint.Fingerprint]:
        if self.public_key and not self._public_fingerprint: 
            self._public_fingerprint = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
            self._public_fingerprint.key = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            return self._public_fingerprint
    
        return None
    
    @abstractmethod
    async def start_socket(self) -> None: ...

    @abstractmethod
    async def establish_secure_channel(self) -> None: ...

    @abstractmethod
    async def handle_key_exchange(self) -> None: ...
    
    async def receive(self, buffer: int) -> bytes:
        data = await self.reader.read(buffer)
        if not data:
            self.logger.warning("[RECEIVE] No data received from peer")

        return data

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    def perform_fingerprint_verification(self, public_key: bytes) -> None:
        fingerprint_ = fingerprint.Fingerprint(hashes.SHA256(), default_backend())
        fingerprint_.key = public_key
        fingerprint_.verify_fingerprint()
        self.logger.info("[FINGERPRINT] Public key fingerprint verified")

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

    def initialize_cipher(self) -> None:
        self.cipher = Cipher(algorithms.AES(self.derived_key), modes.GCM(self.iv))
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    async def verify_derived_keys(self) -> bool:
        key_digest = self.calculate_hash(self.derived_key, hashes.SHA256())

        _, peer_key_digest = await asyncio.gather(
            self.send(key_digest), self.receive(32)  # SHA256
        )

        return key_digest == peer_key_digest