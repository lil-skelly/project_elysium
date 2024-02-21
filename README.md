# Project Elysium
Project Elysium is my first cryptography project and is meant to be the implementation of my strict 2 party communication protocol.

# Deep dive into the protocol
Here is a structured outline of the protocol (nothing too fancy):

1. **Diffie-Hellman**: Both parties use diffie-hellman to establish a shared key which will be used later in the communication to validate both authenticity and integrity. 
2. **Symmetric communication**: Now that both parties have established a shared secret and therefore a *secure* channel they can continue their communication using symmetric encryption schemes like **AES**.

# Measures against MiTM
The biggest *logical* flaw of this protocol is the potential for an active eavesdropper to intercept and manipulate the public key exchange sequence. <br>
If such an interception is carried out successfully, it compromises the entirety of the communication sequence, 
undermining both the authenticity and the integrity of the messages. <br>

In an attempt to overcome the aforementioned vulnerability, the protocol relies on trusted anchors, secondary secure channels to be exact. <br>
Both parties are given a (Bubble Babble)[] encoded version of their pulic key which is then securely exchanged via a secondary channel. <br>
Upon receipt of the other party's public key, the protocol recalculates the fingerprint (utilizing **SHA-256** and subsequently **Bubble Babble** one-way encoding) of the received key and presents it to the user for verification. <br>
This approach delegates the responsibility of verification to the user, providing a robust countermeasure against potential adversaries.
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