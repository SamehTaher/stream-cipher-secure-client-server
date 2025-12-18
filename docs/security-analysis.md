# Security Analysis

## RC4 Security Considerations
RC4 is considered insecure for production use due to known weaknesses,
including keystream bias and lack of built-in authentication. As a result,
this implementation is intended strictly for educational purposes.

## Mitigations Applied
Several mitigations were applied to improve security for the demonstration:

- Use of a random nonce to prevent keystream reuse
- SHA-256-based key derivation
- Discarding the initial portion of the keystream to reduce bias

## Integrity Verification
A SHA-256 hash of the plaintext is generated to verify message integrity
after decryption, ensuring that the data was not altered during transmission.

## Comparison to Modern Ciphers
Modern encryption standards such as AES-GCM and ChaCha20-Poly1305 provide
authenticated encryption and are suitable for real-world systems. These
Algorithms address the weaknesses present in RC4 and are recommended for
production use.

## Disclaimer
This project is designed for academic and educational purposes only and
should not be used in production environments.
