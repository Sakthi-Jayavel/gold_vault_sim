from Crypto.Hash import SHA3_256


def sha3_256_bytes(data: bytes) -> bytes:
    """
    Compute SHA3-256 hash and return raw bytes.
    """
    h = SHA3_256.new()
    h.update(data)
    return h.digest()


def sha3_256_hex(data: bytes) -> str:
    """
    Convenience: return SHA3-256 as hex string.
    """
    h = SHA3_256.new()
    h.update(data)
    return h.hexdigest()
