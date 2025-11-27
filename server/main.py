from typing import Any, Dict, List

from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

import server.database as database
from server import verify_logic

...

status, reasons = verify_logic.classify_event(
    payload_dict,
    hash_valid=hash_valid,
    signature_valid=signature_valid,
)

# Store to DB
db_event = VaultEvent(
    timestamp=payload_dict.get("timestamp"),
    vault_id=payload_dict.get("vault_id"),
    bar_id=payload_dict.get("bar_id"),
    rfid_uid=payload_dict.get("rfid_uid"),
    purity=float(payload_dict.get("purity", 0.0)),
    tamper_status=payload_dict.get("tamper_status"),
    vault_door_status=payload_dict.get("vault_door_status"),
    status=status,
    reason="; ".join(reasons) if reasons else "",
    # gps_lat / gps_lon can be set to None or 0 if your model still has them
    # gps_lat=None,
    # gps_lon=None,
)


class IngestResponse(BaseModel):
    status: str
    reasons: List[str]


app = FastAPI(title="Gold Vault Monitoring – Simulation API")


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    database.init_db()
    print("[Server] Database initialized")


@app.post("/ingest", response_model=IngestResponse)
def ingest(packet: IngestPacket, db: Session = Depends(get_db)):
    # Convert Pydantic object to primitive dict
    packet_dict: Dict[str, Any] = packet.dict()

    # Verify & decrypt
    sensor_data, result = verify_logic.verify_and_decrypt_packet(packet_dict)

    # Log to console (good for screenshots in paper)
    print("\n[Server] Received packet:")
    print(f"  Vault: {sensor_data.get('vault_id')} | Bar: {sensor_data.get('bar_id')}")
    print(f"  RFID: {sensor_data.get('rfid_uid')}")
    print(f"  Purity: {sensor_data.get('purity')}")
    print(f"  GPS: ({sensor_data.get('gps_lat')}, {sensor_data.get('gps_lon')})")
    print(f"  Tamper: {sensor_data.get('tamper_status')}")
    print(f"  Status: {result['status']}")
    if result["reasons"]:
        print("  Reasons:")
        for r in result["reasons"]:
            print(f"    - {r}")
    else:
        print("  All security checks passed.")

    # Persist in DB
    database.save_event(db, sensor_data, result)

    return IngestResponse(status=result["status"], reasons=result["reasons"])
