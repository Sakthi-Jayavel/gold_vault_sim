import base64
import json
import random
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Literal, Optional

import requests

from crypto.aes_utils import encrypt_aes_cbc
from crypto.rsa_utils import load_private_key, sign_sha3_256
from crypto.sha3_utils import sha3_256_bytes

# ------------------- CONFIG -------------------

VAULT_ID = "VLT-001"
BAR_ID = "BAR-001"
EXPECTED_RFID = "TAG12345"

# Server endpoint
SERVER_URL = "http://127.0.0.1:8000/ingest"

TamperStatus = Literal["INTACT", "CUT"]
DoorStatus = Literal["CLOSED", "OPEN", "FORCED_OPEN"]


# ------------------- DATA MODEL (GPS REMOVED) -------------------

@dataclass
class SensorReading:
    timestamp: str
    vault_id: str
    bar_id: str
    rfid_uid: str
    purity: float
    tamper_status: TamperStatus
    vault_door_status: DoorStatus


# ------------------- SENSOR SIMULATION -------------------

def simulate_sensor_reading(scenario: Optional[str] = None) -> SensorReading:
    now = datetime.now(timezone.utc).isoformat()

    purity = random.uniform(98.7, 99.8)
    rfid = EXPECTED_RFID
    tamper: TamperStatus = "INTACT"
    door: DoorStatus = "CLOSED"

    if scenario == "tamper":
        tamper = "CUT"
    elif scenario == "rfid_mismatch":
        rfid = "TAG99999"
    elif scenario == "low_purity":
        purity = random.uniform(94.0, 95.0)
    elif scenario == "vault_open":
        door = "OPEN"
    elif scenario == "forced_open":
        door = "FORCED_OPEN"

    return SensorReading(
        timestamp=now,
        vault_id=VAULT_ID,
        bar_id=BAR_ID,
        rfid_uid=rfid,
        purity=round(purity, 2),
        tamper_status=tamper,
        vault_door_status=door,
    )


# ------------------- SECURE PACKET BUILDING -------------------

def build_secure_packet(reading: SensorReading) -> dict:
    payload_bytes = json.dumps(
        asdict(reading),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    digest = sha3_256_bytes(payload_bytes)

    private_key = load_private_key()
    signature = sign_sha3_256(private_key, digest)

    ciphertext, iv = encrypt_aes_cbc(payload_bytes)

    packet = {
        "vault_id": reading.vault_id,
        "bar_id": reading.bar_id,
        "timestamp": reading.timestamp,
        "payload_ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "hash_sha3_256": base64.b64encode(digest).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }
    return packet


# ------------------- HTTP SEND TO SERVER -------------------

def send_reading(scenario: Optional[str] = None) -> None:
    reading = simulate_sensor_reading(scenario=scenario)

    print("\n[Gateway] Local reading:")
    print(json.dumps(asdict(reading), indent=2))

    packet = build_secure_packet(reading)

    try:
        resp = requests.post(SERVER_URL, json=packet, timeout=5)
        print(f"[Gateway] Sent to {SERVER_URL} -> HTTP {resp.status_code}")
        try:
            print(f"[Gateway] Server reply: {resp.json()}")
        except Exception:
            print(f"[Gateway] Raw reply: {resp.text}")
    except Exception as e:
        print(f"[Gateway] ERROR sending to server: {e}")


# ------------------- MAIN LOOP -------------------

def main():
    scenario: Optional[str] = None
    if len(sys.argv) > 1:
        scenario = sys.argv[1]

    print(f"[Gateway] Starting simulated sensor stream (scenario={scenario})...")

    for i in range(5):
        print(f"\n=== Reading #{i+1} ===")
        send_reading(scenario=scenario)
        time.sleep(1.0)

    print("\n[Gateway] Finished simulation run.")


if __name__ == "__main__":
    main()
