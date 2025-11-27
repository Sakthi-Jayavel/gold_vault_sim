from datetime import datetime
from typing import Any, Dict

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# -------------------- DATABASE SETUP --------------------

# SQLite DB (simple for simulation + papers)
DATABASE_URL = "sqlite:///./vault_events.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for SQLite in FastAPI
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# -------------------- DATABASE MODEL --------------------

class VaultEvent(Base):
    __tablename__ = "vault_events"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Sensor fields
    vault_id = Column(String(50), index=True)
    bar_id = Column(String(50), index=True)
    timestamp = Column(String(100))

    rfid_uid = Column(String(100))
    purity = Column(Float)
    gps_lat = Column(Float)
    gps_lon = Column(Float)
    tamper_status = Column(String(20))
    vault_door_status = Column(String(20))  # OPEN / CLOSED / FORCED_OPEN

    # Security classification
    status = Column(String(20))  # SECURE or BREACH
    reason = Column(Text)        # joined reason list

    # Detailed verification flags
    signature_ok = Column(Boolean)
    hash_ok = Column(Boolean)
    rfid_ok = Column(Boolean)
    gps_ok = Column(Boolean)
    purity_ok = Column(Boolean)
    tamper_ok = Column(Boolean)
    door_ok = Column(Boolean)


# -------------------- INITIALIZATION --------------------

def init_db() -> None:
    """Create tables if database is empty."""
    Base.metadata.create_all(bind=engine)


# -------------------- SAVE EVENT --------------------

def save_event(
    db: Session,
    sensor_data: Dict[str, Any],
    result: Dict[str, Any],
) -> VaultEvent:
    """Insert a verified event into the vault_events table."""

    event = VaultEvent(
        vault_id=sensor_data.get("vault_id"),
        bar_id=sensor_data.get("bar_id"),
        timestamp=sensor_data.get("timestamp"),

        rfid_uid=sensor_data.get("rfid_uid"),
        purity=sensor_data.get("purity"),
        gps_lat=sensor_data.get("gps_lat"),
        gps_lon=sensor_data.get("gps_lon"),
        tamper_status=sensor_data.get("tamper_status"),
        vault_door_status=sensor_data.get("vault_door_status"),

        status=result.get("status"),
        reason="; ".join(result.get("reasons", [])),

        signature_ok=result.get("signature_ok"),
        hash_ok=result.get("hash_ok"),
        rfid_ok=result.get("rfid_ok"),
        gps_ok=result.get("gps_ok"),
        purity_ok=result.get("purity_ok"),
        tamper_ok=result.get("tamper_ok"),
        door_ok=result.get("door_ok"),
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event
