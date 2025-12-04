import base64
import json
from typing import Any, Dict, List, Tuple

from gateway.crypto.aes_utils import decrypt_aes_cbc
from gateway.crypto.rsa_utils import load_private_key, sign_sha3_256
from gateway.crypto.sha3_utils import sha3_256_bytes

EXPECTED_RFID = "TAG12345"
MIN_PURITY_OK = 98.5


def _decode(packet: Dict[str, Any], key: str) -> bytes:
    if key not in packet:
        raise KeyError(f"Missing field: {key}")
    return base64.b64decode(packet[key])


def verify_and_decrypt_packet(packet: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    reasons: List[str] = []
    status = "OK"
    sensor_data: Dict[str, Any] = {}

    try:
        ciphertext = _decode(packet, "payload_ciphertext")
        iv = _decode(packet, "iv")
        digest_packet = _decode(packet, "hash_sha3_256")
        sig_packet = _decode(packet, "signature")

        plaintext = decrypt_aes_cbc(ciphertext, iv)

        digest_local = sha3_256_bytes(plaintext)
        if digest_local != digest_packet:
            reasons.append("SHA3-256 hash mismatch.")

        private_key = load_private_key()
        expected_sig = sign_sha3_256(private_key, digest_packet)
        if expected_sig != sig_packet:
            reasons.append("RSA signature mismatch.")

        sensor_data = json.loads(plaintext.decode("utf-8"))

    except Exception as e:
        reasons.append(f"Crypto/parse error: {e}")
        return {}, {"status": "ALERT", "reasons": reasons}

    # Add outer metadata
    sensor_data.setdefault("vault_id", packet.get("vault_id"))
    sensor_data.setdefault("bar_id", packet.get("bar_id"))
    sensor_data.setdefault("timestamp", packet.get("timestamp"))

    # -------- POLICY --------

    # RFID
    rfid = sensor_data.get("rfid_uid")
    if rfid != EXPECTED_RFID:
        reasons.append(f"RFID mismatch: {rfid}")

    # Tamper
    if sensor_data.get("tamper_status") == "CUT":
        reasons.append("Tamper mesh CUT.")

    # Door
    door = sensor_data.get("vault_door_status")
    if door == "FORCED_OPEN":
        reasons.append("Vault door FORCED_OPEN.")
    elif door == "OPEN":
        reasons.append("Vault door OPEN.")

    # Purity
    purity = sensor_data.get("purity")
    try:
        if float(purity) < MIN_PURITY_OK:
            reasons.append(f"Purity below threshold: {purity}")
    except:
        reasons.append("Invalid purity reading.")

    # Determine final status
    if any(x.lower().startswith(("crypto", "sha3", "rsa", "tamper", "rfid", "forced")) for x in reasons):
        status = "ALERT"
    elif reasons:
        status = "WARN"
    else:
        status = "OK"

    return sensor_data, {"status": status, "reasons": reasons}
