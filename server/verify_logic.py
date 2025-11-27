# server/verify_logic.py

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Tuple, Optional

from server.database import SessionLocal, VaultEvent

# You can later move these into config or DB
PURITY_MIN = 99.0          # minimum allowed purity %
EXPECTED_RFID_BY_BAR = {   # simple mapping for now
    "BAR-001": "TAG12345",
    # add more bars here if needed
}


def _get_expected_rfid(bar_id: str, rfid_uid: str) -> str:
    """
    Return the expected RFID UID for a given bar_id.
    If not configured, we assume the *first* RFID seen is the canonical one.
    """
    if bar_id in EXPECTED_RFID_BY_BAR:
        return EXPECTED_RFID_BY_BAR[bar_id]

    # If this is the first time we see this bar, treat current RFID as canonical.
    EXPECTED_RFID_BY_BAR[bar_id] = rfid_uid
    return rfid_uid


def _get_last_event_time(bar_id: str) -> Optional[datetime]:
    """
    Fetch the last event timestamp for this bar from DB.
    Used for replay detection. Returns None if no previous event.
    """
    db = SessionLocal()
    try:
        last = (
            db.query(VaultEvent)
            .filter(VaultEvent.bar_id == bar_id)
            .order_by(VaultEvent.timestamp.desc())
            .first()
        )
        return last.timestamp if last is not None else None
    finally:
        db.close()


def classify_event(
    payload: Dict,
    *,
    hash_valid: bool,
    signature_valid: bool,
) -> Tuple[str, List[str]]:
    """
    Core SECURE/BREACH decision logic.

    Parameters
    ----------
    payload : dict
        Decrypted event payload from gateway. Expected keys:
        - timestamp (ISO string or already datetime)
        - vault_id
        - bar_id
        - rfid_uid
        - purity (float)
        - tamper_status  ("INTACT", "CUT", "ALARM", ...)
        - vault_door_status ("OPEN", "CLOSED")
        NOTE: gps_lat/gps_lon are deliberately IGNORED now.

    hash_valid : bool
        Result of SHA-3 integrity check.

    signature_valid : bool
        Result of RSA-3072 signature verification.

    Returns
    -------
    status : str
        "SECURE" or "BREACH"

    reasons : list of str
        Human-readable reasons explaining why the event is BREACH.
        Empty list for SECURE events.
    """

    reasons: List[str] = []

    # ---- 0) Parse and normalize fields ----
    vault_id: str = payload.get("vault_id", "")
    bar_id: str = payload.get("bar_id", "")
    rfid_uid: str = payload.get("rfid_uid", "")
    tamper_status: str = payload.get("tamper_status", "UNKNOWN")
    vault_door_status: str = payload.get("vault_door_status", "UNKNOWN")

    try:
        purity = float(payload.get("purity", 0.0))
    except (TypeError, ValueError):
        purity = 0.0

    # timestamp: allow ISO string or datetime
    ts_raw = payload.get("timestamp")
    if isinstance(ts_raw, datetime):
        timestamp = ts_raw
    else:
        # assume ISO string
        try:
            timestamp = datetime.fromisoformat(str(ts_raw))
        except Exception:
            timestamp = None

    # ---- 1) Crypto integrity (highest priority) ----
    if not hash_valid or not signature_valid:
        reasons.append("Payload hash/signature invalid (integrity failure)")
        return "BREACH", reasons

    # If timestamp is completely invalid, treat as suspicious
    if timestamp is None:
        reasons.append("Invalid or missing timestamp")
        return "BREACH", reasons

    # ---- 2) Tamper mesh ----
    if tamper_status != "INTACT":
        reasons.append(f"Tamper mesh status = {tamper_status}")
        return "BREACH", reasons

    # ---- 3) RFID identity check ----
    expected_rfid = _get_expected_rfid(bar_id, rfid_uid)
    if rfid_uid != expected_rfid:
        reasons.append("RFID UID mismatch for this bar")
        return "BREACH", reasons

    # ---- 4) Purity threshold ----
    if purity < PURITY_MIN:
        reasons.append(
            f"Purity below threshold ({purity:.2f}% < {PURITY_MIN:.2f}%)"
        )
        return "BREACH", reasons

    # ---- 5) Door logic (basic version) ----
    # NOTE: We keep this simple for now. You can later extend with movement detection.
    if vault_door_status == "OPEN" and bar_id == "":
        reasons.append("Vault door opened without associated bar_id/RFID")
        return "BREACH", reasons

    # ---- 6) Replay detection ----
    last_ts = _get_last_event_time(bar_id)
    if last_ts is not None and timestamp <= last_ts:
        reasons.append("Timestamp older than or equal to last event (possible replay)")
        return "BREACH", reasons

    # If all checks passed:
    return "SECURE", reasons
