
# encrypt_message.py
# Step 2 – Message Encryption using RC4 (from rc4.py)

from rc4 import RC4, derive_stream_key
import os

# Shared password (for this demo only)
PASSWORD = "COIS4370-SymmetricKeyDemo"

# Create a meaningful plaintext message (>=100 chars)
PLAINTEXT = (
    "In modern cybersecurity, symmetric encryption ensures data confidentiality between parties "
    "sharing a secret key. This demo uses a custom RC4 implementation for educational purposes."
)

# Generate a random 16-byte nonce so each run uses a new derived key
nonce = os.urandom(16)

# Derive the per-message key using SHA-256(nonce || password)
key = derive_stream_key(PASSWORD, nonce)

# Initialize RC4 cipher and encrypt
rc4 = RC4(key, drop_n=768)
ciphertext = rc4.crypt(PLAINTEXT.encode("utf-8"))

# Display results
print("Plaintext length:", len(PLAINTEXT))
print("Nonce (hex):", nonce.hex())
print("Ciphertext (hex):", ciphertext.hex())
