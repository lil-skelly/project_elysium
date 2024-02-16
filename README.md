# Project Elysium
Project Elysium is my first cryptography project and is meant to be the implementation of my strict 2 party communication protocol.

# Deep dive into the protocol
Here is a structured outline of the protocol (nothing too fancy):

1. **Diffie-Hellman**: Both parties use diffie-hellman to establish a shared key which will be used later in the communication to validate both authenticity and integrity. 
2. **Key exchange**: The server shares its' RSA public key with the client (not really an exchange).
3. **Handshake packet transaction**: 
The client encrypts a packet* containing the session key and nonce using the server's RSA public key and proceeds to send it to the server.
The server receives the encrypted packet and decodes it with its' own RSA private key.
4. **Server side preparation**: 
The server recreates an AES cipher using the session key and nonce obtained from the **handshake packet**.
## End of Handshake
5. **Symmetric communication**: Both parties have now established a secure communication channel.
They will proceed with AES encrypting and digesting their messages, 
packing the message and digesting it using JSON with base64 encoding and sending it to the other.

# Advantages/Disadvantages
- **E2E**: The data are end-to-end encrypted and are/can only be decrypted when they reach the other party.
- **Hybrid encryption**: The protocol utilizes both symmetric (AES) and assymetric (RSA) encryption schemes to increase security.
- **Authenticity and integrity**: This protocol ensures authenticity and integrity for the vast majority* of the communication
- **Confidentiality**: This is a result of the 2 party communication scheme described below.
- **Strict 2 party communication**. It's not a bug its a feature! <br>
This unusual way of communication reduces the attack surface area and therefore eliminates <br>
a lot of vulnerabilities and also keeps things simple for further development/maintenance.
The two parties enjoy more privacy because there are fewer intermediaries involved in the exchange of information.
- **Efficiency**: Direct communications between two parties can be more efficient bandwidth wise.

- ***Unsecure implementation**:
As of **NOW** the public RSA key is communicated from the server to the client unsecurely.
I am planning to add as soon as I can the actual **Step 1** to the implementation which should solidify it.
This is **NOT** a problem of the protocol, I just decided to use DH after the implementation was mostly finished.