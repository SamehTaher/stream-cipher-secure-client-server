# client.py — sender side
# Encrypts plaintext with RC4, sends (nonce + ciphertext) to server.

import socket, os
from rc4 import RC4, derive_stream_key

HOST = "127.0.0.1"
PORT = 5001
PASSWORD = "COIS4370-SymmetricKeyDemo"

PLAINTEXT = (
    "This message demonstrates symmetric encryption using a custom RC4 implementation. "
    "It is sent over a local TCP socket for COIS4370 Assignment 2."
)

# Generate 16-byte random nonce and derive a per-message key
nonce = os.urandom(16)
key = derive_stream_key(PASSWORD, nonce)

# Encrypt plaintext with RC4 (same function decrypts)
rc4 = RC4(key, drop_n=768)
ciphertext = rc4.crypt(PLAINTEXT.encode())

# Combine nonce + ciphertext so the receiver can reconstruct the key
payload = nonce + ciphertext

print(f"[CLIENT] Connecting to {HOST}:{PORT}...")
with socket.create_connection((HOST, PORT)) as sock:
    sock.sendall(payload)
    print(f"[CLIENT] Sent {len(payload)} bytes (16B nonce + {len(ciphertext)}B ciphertext).")

print("[CLIENT] Done.")
