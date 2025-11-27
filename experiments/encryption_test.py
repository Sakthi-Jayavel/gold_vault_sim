import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt

from gateway.crypto.aes_utils import encrypt_aes_cbc, decrypt_aes_cbc
from gateway.crypto.rsa_utils import (
    load_private_key,
    load_public_key,
    sign_sha3_256,
    verify_sha3_256,
)
from gateway.crypto.sha3_utils import sha3_256_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = PROJECT_ROOT / "paper_assets" / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)


def time_operation(func, *args, repeats=20):
    durations = []
    for _ in range(repeats):
        start = time.perf_counter()
        func(*args)
        end = time.perf_counter()
        durations.append((end - start) * 1000.0)  # ms
    avg = statistics.mean(durations)
    stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
    return avg, stdev


def main():
    print("[Experiment] Encryption Performance Test")

    private_key = load_private_key()
    public_key = load_public_key()

    payload_sizes = [256, 512, 1024]  # bytes

    aes_enc_avgs = []
    rsa_sign_avgs = []
    rsa_verify_avgs = []

    for size in payload_sizes:
        print(f"\n--- Payload size: {size} bytes ---")
        payload = b"A" * size

        # SHA3 (just printed, not graphed right now)
        sha_avg, sha_std = time_operation(sha3_256_bytes, payload)
        print(f"SHA3-256 hash  -> avg = {sha_avg:.3f} ms")

        # AES encrypt
        def enc_only():
            encrypt_aes_cbc(payload)

        aes_enc_avg, aes_enc_std = time_operation(enc_only)
        aes_enc_avgs.append(aes_enc_avg)
        print(f"AES-256 encrypt -> avg = {aes_enc_avg:.3f} ms")

        # AES enc+dec
        def enc_dec():
            ct, iv = encrypt_aes_cbc(payload)
            decrypt_aes_cbc(ct, iv)

        aes_encdec_avg, aes_encdec_std = time_operation(enc_dec)
        print(f"AES-256 enc+dec -> avg = {aes_encdec_avg:.3f} ms")

        # RSA sign
        def sign_only():
            h = sha3_256_bytes(payload)
            sign_sha3_256(private_key, h)

        rsa_sign_avg, rsa_sign_std = time_operation(sign_only)
        rsa_sign_avgs.append(rsa_sign_avg)
        print(f"RSA-3072 sign   -> avg = {rsa_sign_avg:.3f} ms")

        # RSA verify
        def verify_only():
            h = sha3_256_bytes(payload)
            sig = sign_sha3_256(private_key, h)
            verify_sha3_256(public_key, h, sig)

        rsa_verify_avg, rsa_verify_std = time_operation(verify_only)
        rsa_verify_avgs.append(rsa_verify_avg)
        print(f"RSA-3072 verify -> avg = {rsa_verify_avg:.3f} ms")
    print("\n========================")
    print(" PERFORMANCE SUMMARY")
    print("========================")

    print("\nPayload Size | AES Encrypt (ms) | RSA Sign (ms) | RSA Verify (ms)")
    print("---------------------------------------------------------------")

    for i, size in enumerate(payload_sizes):
        print(f"{size:12} | "
              f"{aes_enc_avgs[i]:16.3f} | "
              f"{rsa_sign_avgs[i]:13.3f} | "
              f"{rsa_verify_avgs[i]:15.3f}")

    # --------- Plot graph ---------
    plt.figure()
    plt.plot(payload_sizes, aes_enc_avgs, marker="o", label="AES-256 encrypt")
    plt.plot(payload_sizes, rsa_sign_avgs, marker="o", label="RSA-3072 sign")
    plt.plot(payload_sizes, rsa_verify_avgs, marker="o", label="RSA-3072 verify")
    plt.xlabel("Payload size (bytes)")
    plt.ylabel("Average time (ms)")
    plt.title("Encryption/Signature Time vs Payload Size")
    plt.legend()
    plt.grid(True)

    out_path = FIG_DIR / "encryption_performance.png"
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    print(f"\n[Experiment] Saved graph to: {out_path}")


if __name__ == "__main__":
    main()
