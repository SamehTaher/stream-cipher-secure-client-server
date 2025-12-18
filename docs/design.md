Encryption and Communication Overview

This project implements the RC4 stream cipher from scratch in Python to demonstrate symmetric encryption concepts. 
The implementation includes both the Key Scheduling Algorithm (KSA) and the Pseudo-Random Generation Algorithm (PRGA), 
with a keystream drop of 768 bytes to reduce early bias. A unique encryption key is derived per message by combining a random nonce with a shared password using SHA-256, preventing key and keystream reuse.

Encrypted messages are transmitted using a TCP client–server model built with Python sockets. The client encrypts and sends the ciphertext and nonce, 
while the server derives the same key, decrypts the message, and verifies integrity using a SHA-256 hash. Socket reuse and error-tolerant decoding were implemented to ensure reliable operation during development.

RC4 is used strictly for educational purposes, as it is not suitable for production due to known weaknesses such as keystream bias and lack of authentication. 
Modern ciphers like AES-GCM or ChaCha20-Poly1305 are recommended for real-world secure communication.
