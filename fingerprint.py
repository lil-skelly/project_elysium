from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
import socket
import logging
import os

logging.basicConfig(level=logging.INFO)

def get_user_confirmation(prompt: str):
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
        known_fingerprints: str = None,
    ) -> None:
        self.algorithm = algorithm
        self.backend = backend

        if not known_fingerprints or not os.path.exists(known_fingerprints):
            logging.error("[!] Invalid known_fingerprints path. <verify key> will follow manual verification.")
        else:
            with open(known_fingerprints, "r") as fd:
                self.known_fingerprints = set()
                for print_ in fd.readlines():
                    self.known_fingerprints.add(print_.strip())

    def verify_key(self) -> None:
        logging.info(f"[*] Party's key fingerprint:\n{self.fingerprint}")
        if self.known_fingerprints:
            for print_ in self.known_fingerprints:
                data = print_.split("   ")
                if self.fingerprint == data[1].strip():
                    logging.info("[*] Fingerprint found in provided <known_fingerprints> file.")
                    
                    if not get_user_confirmation(f"[?] Is {data[0]} the person you are trying to contact [Y/n] "):
                        logging.critical(f"[HIJACK] {data[0]} is trying to intercept your communication.")
                        logging.critical("[!] Exiting to prevent *potential* security breach. >Investigate immediatly<")
                        return False
                    else:
                        return True

            
        if not get_user_confirmation("[?] Do you recognize this SHA-256 fingerprint of the key? [Y/n] "):
            logging.critical("[HIJACK] Someone is trying to intercept your communication.")
            logging.critical("[!] Exiting to prevent *potential* security breach. >Investigate immediatly<")
            return False
                
        return True

    def create_fingerprint(self, key: bytes) -> None:
        hasher = hashes.Hash(
            algorithm=self.algorithm,
            backend=self.backend
        )
        hasher.update(key)
        self.fingerprint = base64.b64encode(hasher.finalize()).decode()


fingerprint = Fingerprint(
    algorithm=hashes.SHA256(),
    backend=default_backend(),
    known_fingerprints="./known_fingerprints"
)
with open("./known_fingerprints", "w") as fd:
    pass
    
with open("./known_fingerprints", "w") as fd:
    for key in ["hello", "love", "dog", "cat", "mary", "john"]:
        fingerprint.create_fingerprint(key.encode())
        logging.info(fingerprint.fingerprint)
        packet = f"{key}    {fingerprint.fingerprint}\n"
        fd.write(packet) 

fingerprint.create_fingerprint(b"john")
fingerprint.verify_key()