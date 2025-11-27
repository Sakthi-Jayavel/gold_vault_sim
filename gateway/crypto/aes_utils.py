import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# 32-byte AES-256 key (simulation only)
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # exactly 32 bytes
assert len(AES_KEY) == 32


BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    return data[:-pad_len]


def encrypt_aes_cbc(plaintext: bytes) -> Tuple[bytes, bytes]:
    """AES-256-CBC encrypt → returns (ciphertext, iv)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = _pkcs7_pad(plaintext)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def decrypt_aes_cbc(ciphertext: bytes, iv: bytes) -> bytes:
    """AES-256-CBC decrypt → returns original plaintext (EXACT match)."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)
