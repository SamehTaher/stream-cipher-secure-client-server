# rc4.py
# Pure-Python RC4 implementation KSA + PRGA with optional keystream drop.
# Educational use only

from typing import Iterable
import hashlib

class RC4:
    """
    RC4 stream cipher implementation.
    - key: bytes-like key (any length > 0)
    - drop_n: number of initial keystream bytes to discard (mitigates early-byte biases)
    """
    def __init__(self, key: bytes, drop_n: int = 768):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        if len(key) == 0:
            raise ValueError("key must not be empty")
        self.key = bytes(key)
        self.drop_n = int(drop_n)

    def _ksa(self) -> list:
        """Key Scheduling Algorithm: initialize S as a permutation of 0..255."""
        S = list(range(256))
        j = 0
        keylen = len(self.key)
        for i in range(256):
            j = (j + S[i] + self.key[i % keylen]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def _prga(self, S: list) -> Iterable[int]:
        """
        Pseudo-Random Generation Algorithm: yields keystream bytes.
        Optionally drop the first `drop_n` bytes to reduce known biases.
        """
        i = 0
        j = 0
        # optional keystream drop
        for _ in range(self.drop_n):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            _ = S[(S[i] + S[j]) % 256]  # discard

        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            yield K

    def crypt(self, data: bytes) -> bytes:
        """
        Encrypt or decrypt (same operation for RC4 stream cipher).
        Returns bytes of the same length as "data".
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")
        S = self._ksa()
        keystream = self._prga(S)
        out = bytearray(len(data))
        for idx, b in enumerate(data):
            out[idx] = b ^ next(keystream)
        return bytes(out)


def derive_stream_key(password: str, nonce: bytes) -> bytes:
    """
    Simple per-message key derivation: SHA-256(nonce || password) -> 32 bytes key.
    This is used here to avoid reusing the same RC4 key across messages.
    Not a production KDF — educational only.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("nonce must be bytes")
    h = hashlib.sha256()
    h.update(nonce)
    h.update(password.encode("utf-8"))
    return h.digest()


# -------------------------
# Quick self-test (can run: python rc4.py)
# -------------------------
if __name__ == "__main__":
    PASSWORD = "test-password"
    nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"  # example 16B nonce
    key = derive_stream_key(PASSWORD, nonce)
    rc4 = RC4(key, drop_n=768)

    plaintext = b"RC4 test message: this plaintext is > 100 chars to satisfy the assignment. " \
                b"It demonstrates encryption and decryption using a from-scratch RC4 in Python."
    # Encryption
    ciphertext = rc4.crypt(plaintext)
    # Decrypt using a fresh RC4 instance (new internal state)
    rc4_dec = RC4(key, drop_n=768)
    recovered = rc4_dec.crypt(ciphertext)

    print("Plaintext length:", len(plaintext))
    print("Ciphertext (hex):", ciphertext.hex()[:120] + "..." if len(ciphertext) > 60 else ciphertext.hex())
    print("Recovered equals original:", recovered == plaintext)
    if recovered != plaintext:
        print("ERROR: mismatch (not expected in correct implementation)")
    else:
        print("Recovered plaintext (utf-8):")
        print(recovered.decode("utf-8"))

