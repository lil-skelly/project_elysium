from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
import socket
import logging
import os
import string

logging.basicConfig(level=logging.INFO)


def get_user_confirmation(prompt: str) -> True:
    while True:
        response = input(prompt).lower()
        if response in {"y", "n"}:
            return response == "y"
        else:
            print("[>w<] Invalid input. Enter 'y' or 'n'.")


class Fingerprint:
    def __init__(
        self,
        algorithm: hashes.HashAlgorithm,
        backend=None,
    ) -> None:
        self.algorithm = algorithm  # Hashing algorithm
        self.backend = backend  # Optional backend

        self.fingerprint = None  # The fingerprints actual fingerprint

        self._key = None  # key bytes (private attr. use Fingerprint.key)

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: bytes):
        if isinstance(key, bytes):
            self._key = key
            self.create_fingerprint()
        else:
            raise ValueError(f"[!] <key> must be of type bytes ({type(key)} given)")

    def verify_fingerprint(self):
        logging.info(f"[*] Party's key fingerprint:\n{self.bubble_babble()}")
        if not get_user_confirmation(
            "[?] Do you recognize this SHA-256 fingerprint of the key? [y/n] "
        ):
            logging.critical(
                "[HIJACK] Someone is trying to intercept your communication."
            )
            logging.critical(
                "[!] Exiting to prevent *potential* security breach. >Investigate immediatly<"
            )
            exit(1)

    def create_fingerprint(self) -> None:
        hasher = hashes.Hash(algorithm=self.algorithm, backend=self.backend)
        hasher.update(self.key)
        self.fingerprint = base64.b64encode(hasher.finalize()).decode()

    def bubble_babble(self) -> str:
        VOWELS = list('aeiouy')
        CONSONANTS = list('bcdfghklmnprstvzx')
        mval = [ord(str(x)) for x in self.fingerprint]
        seed = 1
        mlen = len(mval)
        rounds = mlen // 2 + 1
        encparts = ['x']
        eextend = encparts.extend
        for i in range(rounds):
            if (i + 1 < rounds) or (mlen % 2 != 0):
                imval2i = int(mval[2 * i])
                idx0 = (((imval2i >> 6) & 3) + seed) % 6
                idx1 = (imval2i >> 2) & 15
                idx2 = ((imval2i & 3) + seed // 6) % 6
                eextend([VOWELS[idx0], CONSONANTS[idx1], VOWELS[idx2]])
                if (i + 1 < rounds):
                    imval2i1 = int(mval[2 * i + 1])
                    idx3 = (imval2i1 >> 4) & 15
                    idx4 = imval2i1 & 15
                    eextend([CONSONANTS[idx3], '-', CONSONANTS[idx4]])
                    seed = (seed * 5 + imval2i * 7 + imval2i1) % 36
            else:
                idx0 = seed % 6
                idx1 = 16
                idx2 = seed // 6
                eextend([VOWELS[idx0], CONSONANTS[idx1], VOWELS[idx2]])
        eextend(['x'])
        encoded = ''.join(encparts)
        return encoded