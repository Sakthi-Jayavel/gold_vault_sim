from typing import Any, Dict, List

from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

import server.database as database
from server import verify_logic


class IngestPacket(BaseModel):
    vault_id: str
    bar_id: str
    timestamp: str

    payload_ciphertext: str
    iv: str
    hash_sha3_256: str
    signature: str


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
    print("[Server] /ingest called")

    packet_dict: Dict[str, Any] = packet.dict()

    sensor_data, result = verify_logic.verify_and_decrypt_packet(packet_dict)

    print("\n[Server] Received packet:")
    print(f"  Vault: {sensor_data.get('vault_id')} | Bar: {sensor_data.get('bar_id')}")
    print(f"  RFID: {sensor_data.get('rfid_uid')}")
    print(f"  Purity: {sensor_data.get('purity')}")
    print(f"  Tamper: {sensor_data.get('tamper_status')}")
    print(f"  Door: {sensor_data.get('vault_door_status')}")
    print(f"  Status: {result['status']}")

    if result["reasons"]:
        print("  Reasons:")
        for r in result["reasons"]:
            print(f"    - {r}")
    else:
        print("  All security checks passed.")

    database.save_event(db, sensor_data, result)

    return IngestResponse(status=result["status"], reasons=result["reasons"])
