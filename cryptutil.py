from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    CipherContext,
)
import os


class CryptUtils:
    def __init__(self) -> None:
        self._key = None
        self._aesgcm = None

    @property
    def nonce(self):
        return os.urandom(12)
    
    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: bytes):
        self._key = key
        self._aesgcm = AESGCM(key)
    
    def calculate_hash(self, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        """
        Calculate the hash of the given data using the specified hashing algorithm.

        Parameters
        ----------
        data
            Data to hash.
        algorithm
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

    def sign_with_hmac(
        self, data: bytes
    ) -> bytes:
        """
        Sign `data` using the instance's HMAC context.
        To create a HMAC context call initialize_cipher

        Parameters
        ----------
        data
            Data to sign

        Returns
        -------
        bytes
            Signature of the data
        """        
        hmac_ctx = self._hmac_context.copy()
        hmac_ctx.update(data)
        signature = hmac_ctx.finalize()

        return signature