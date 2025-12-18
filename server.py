# server.py — receiver side
# Accepts incoming ciphertext and stores it locally.

import socket, pathlib

HOST = "127.0.0.1"
PORT = 5001
OUT_DIR = pathlib.Path("received_data")
OUT_DIR.mkdir(exist_ok=True)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}...")
    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected from {addr}")
        data = bytearray()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)

        # Save raw ciphertext for later verification
        out_file = OUT_DIR / "ciphertext_received.bin"
        out_file.write_bytes(data)
        print(f"[SERVER] Received {len(data)} bytes. Saved to {out_file.resolve()}")

print("[SERVER] Done.")
