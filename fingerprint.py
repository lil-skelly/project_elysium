import base64
import logging
from typing import Optional
from cryptography.hazmat.primitives import hashes
import utils


logging.basicConfig(level=logging.INFO)

class Fingerprint:
    """Class which represents the fingerprint of a public key."""
    def __init__(self, algorithm: hashes.HashAlgorithm) -> None:
        self.algorithm: hashes.HashAlgorithm = algorithm  # Hashing algorithm

        self.fingerprint: Optional[str] = None  # The actual fingerprint
        self._key: Optional[bytes] = None  # key bytes (private attr. use Fingerprint.key)

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: bytes):
        if not isinstance(key, bytes):
            raise ValueError(f"[!] <key> must be of type bytes ({type(key)} given)")
        self._key = key
        self._create_fingerprint()

    def verify_fingerprint(self):
        """Prompt the user to manually identify the fingerprint"""
        logging.info(f"[*] Party's key fingerprint:\n{self.get_bubble_babble()}")
        if not utils.get_user_confirmation(
            "[?] Do you recognize this SHA-256 fingerprint of the key? [y/n] "
        ):
            logging.critical(
                "[HIJACK] Someone is trying to intercept your communication."
            )
            logging.critical(
                "[!] Exiting to prevent *potential* security breach. >Investigate immediatly<"
            )
            exit(1)

    def _create_fingerprint(self) -> None:
        """
        Create the fingerprint using the specified hash algorithm.
        Private method, set key attribute to generate an up-to-date fingerprint of the key.
        """
        hasher = hashes.Hash(algorithm=self.algorithm)
        hasher.update(self.key)
        self.fingerprint = base64.b64encode(hasher.finalize()).decode()

    def get_bubble_babble(self) -> str:
        """Create a pronouncable version of the fingerprint using the bubble-babble algorithm

        Returns
        -------
        str
            The bubble-babble encoded version of the fingerprint
        """
        VOWELS = list('aeiouy')
        CONSONANTS = list('bcdfghklmnprstvzx')
        mval = [ord(x) for x in self.fingerprint]
        seed = 1
        mlen = len(mval)
        rounds = (mlen // 2) + 1
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