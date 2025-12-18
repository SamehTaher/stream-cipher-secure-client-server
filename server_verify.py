# ===============================================================
# COIS4370 - Assignment 2
# Step 4: Verification and Analysis (Server Side)
# ===============================================================

import socket, pathlib, hashlib
from rc4 import RC4, derive_stream_key  # custom RC4 implementation (from rc4.py)

# --- Configuration ---
HOST = "127.0.0.1"              # Localhost (loopback interface)
PORT = 5001                     # Must match client port
PASSWORD = "COIS4370-SymmetricKeyDemo"
OUT_DIR = pathlib.Path("received_data")
OUT_DIR.mkdir(exist_ok=True)    # Create folder if missing

# --- Server socket setup ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse port if in TIME_WAIT
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}...")

    # Wait for client connection
    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected from {addr}")

        # --- Receive incoming data ---
        # Data format: [16-byte nonce][ciphertext bytes]
        data = bytearray()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)

        # --- Separate nonce and ciphertext ---
        nonce, ciphertext = data[:16], data[16:]
        print(f"[SERVER] Received {len(ciphertext)} bytes of ciphertext.")

        # Save ciphertext for record
        (OUT_DIR / "ciphertext_received.bin").write_bytes(ciphertext)

        # --- Key derivation & decryption ---
        # Same derivation as sender: SHA-256(nonce || password)
        key = derive_stream_key(PASSWORD, nonce)
        rc4 = RC4(key, drop_n=768)  # drop_n removes biased keystream prefix
        plaintext = rc4.crypt(ciphertext)

        # Convert bytes to UTF-8 string for readability
        decrypted_text = plaintext.decode("utf-8", errors="ignore")

        # --- Integrity verification ---
        # A simple SHA-256 hash of plaintext ensures that decryption
        # yielded the same message as the original.
        digest = hashlib.sha256(plaintext).hexdigest()

        # Save plaintext output
        (OUT_DIR / "decrypted.txt").write_text(decrypted_text, encoding="utf-8")

        # --- Display summary ---
        print("\n[SERVER] --- Verification Summary ---")
        print(f"Nonce (hex): {nonce.hex()}")
        print(f"SHA-256 (plaintext): {digest}")
        print(f"Decrypted message:\n{decrypted_text}\n")
        print(f"[SERVER] Output saved in folder: {OUT_DIR.resolve()}")

print("[SERVER] Done.")
