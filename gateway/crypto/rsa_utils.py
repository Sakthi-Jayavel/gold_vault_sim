from pathlib import Path
from typing import Tuple

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Resolve project root: gold_vault_sim/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
KEY_DIR = PROJECT_ROOT / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "public_key.pem"


def ensure_key_dir() -> None:
    KEY_DIR.mkdir(exist_ok=True)


def generate_and_save_rsa_keys(key_size: int = 3072) -> None:
    """
    Generate RSA keypair and save to keys/private_key.pem and keys/public_key.pem
    """
    ensure_key_dir()
    print(f"[RSA] Generating {key_size}-bit RSA keypair...")
    key = RSA.generate(key_size)

    private_pem = key.export_key()
    public_pem = key.public_key().export_key()

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    print(f"[RSA] Private key saved to: {PRIVATE_KEY_PATH}")
    print(f"[RSA] Public key saved to : {PUBLIC_KEY_PATH}")


def load_private_key() -> RSA.RsaKey:
    """
    Load RSA private key from file.
    """
    data = PRIVATE_KEY_PATH.read_bytes()
    return RSA.import_key(data)


def load_public_key() -> RSA.RsaKey:
    """
    Load RSA public key from file.
    """
    data = PUBLIC_KEY_PATH.read_bytes()
    return RSA.import_key(data)


def sign_sha3_256(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """
    Sign data (already bytes) using SHA3-256 + RSA-PKCS1v1.5
    """
    h = SHA3_256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_sha3_256(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature with SHA3-256.
    Returns True if valid, False otherwise.
    """
    h = SHA3_256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    # Run this file once to generate RSA keys
    generate_and_save_rsa_keys()

