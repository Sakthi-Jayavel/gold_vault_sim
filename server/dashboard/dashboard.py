import os
import sys
import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session

# -------------------------------------------
# FIX PYTHON PATH FOR STREAMLIT
# -------------------------------------------
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Now import works
from server.database import SessionLocal, VaultEvent


# -------------------------------------------
# LOAD EVENTS FROM DB
# -------------------------------------------
def load_events():
    db: Session = SessionLocal()
    events = db.query(VaultEvent).order_by(VaultEvent.created_at.desc()).all()
    db.close()

    rows = []
    for e in events:
        rows.append({
            "Time": e.timestamp,
            "Vault": e.vault_id,
            "Bar": e.bar_id,
            "RFID": e.rfid_uid,
            "Purity": e.purity,
            "GPS Lat": e.gps_lat,
            "GPS Lon": e.gps_lon,
            "Tamper": e.tamper_status,
            "Door": e.vault_door_status,
            "Status": e.status,
            "Reason": e.reason,
            "Hash OK": e.hash_ok,
            "Signature OK": e.signature_ok,
            "RFID OK": e.rfid_ok,
            "GPS OK": e.gps_ok,
            "Purity OK": e.purity_ok,
            "Tamper OK": e.tamper_ok,
            "Door OK": e.door_ok,
        })
    return pd.DataFrame(rows)


# -------------------------------------------
# STREAMLIT DASHBOARD
# -------------------------------------------

st.set_page_config(
    page_title="Secure Gold Vault Monitor",
    layout="wide",
    page_icon="🟡",
)

st.title("🔐 Secure Gold Vault Monitoring Dashboard")
st.caption("Real-time feed of cryptographically-verified vault sensor events")

df = load_events()

if df.empty:
    st.warning("No events found in database yet. Run the gateway to generate logs.")
else:
    # Status filter
    filt_status = st.selectbox(
        "Filter by status:", ["ALL", "SECURE", "BREACH"], index=0
    )

    if filt_status != "ALL":
        df = df[df["Status"] == filt_status]

    # Show latest events
    st.dataframe(df, use_container_width=True)

    # Breach summary
    breaches = df[df["Status"] == "BREACH"]
    if not breaches.empty:
        st.error(f"⚠ Total Breaches: {len(breaches)}")
    else:
        st.success("No breaches detected.")
