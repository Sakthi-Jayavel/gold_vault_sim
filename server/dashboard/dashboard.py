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

# Now import DB session + model
from server.database import SessionLocal, VaultEvent  # type: ignore


# -------------------------------------------
# LOAD EVENTS FROM DB
# -------------------------------------------

def load_events() -> pd.DataFrame:
    """
    Read all vault events from the database and return as a DataFrame.
    Only uses the core fields that we know exist.
    """
    db: Session = SessionLocal()
    try:
        events = (
            db.query(VaultEvent)
            .order_by(VaultEvent.created_at.desc())
            .all()
        )
    finally:
        db.close()

    rows = []
    for e in events:
        rows.append(
            {
                "Time": e.timestamp,
                "Vault": e.vault_id,
                "Bar": e.bar_id,
                "RFID": getattr(e, "rfid_uid", None),
                "Purity": getattr(e, "purity", None),
                "Tamper": getattr(e, "tamper_status", None),
                "Door": getattr(e, "vault_door_status", None),
                "Status": getattr(e, "status", None),
                "Reason": getattr(e, "reason", None),
            }
        )

    return pd.DataFrame(rows)


# -------------------------------------------
# STREAMLIT DASHBOARD
# -------------------------------------------

st.set_page_config(
    page_title="Secure Gold Vault Monitor",
    layout="wide",
    page_icon="🪙",
)

st.title("🔐 Secure Gold Vault Monitoring Dashboard")
st.caption("Real-time feed of cryptographically-verified vault sensor events")

df = load_events()

if df.empty:
    st.warning("No events found in database yet. Run the gateway to generate logs.")
else:
    # --- Status Filter ---
    status_options = ["ALL", "OK", "WARN", "ALERT", "BREACH"]
    filt_status = st.selectbox("Filter by status:", status_options, index=0)

    # Normalize to upper-case for comparisons
    df["Status"] = df["Status"].astype(str)

    if filt_status == "ALL":
        filtered_df = df
    elif filt_status == "BREACH":
        # Treat BREACH as equivalent to ALERT events
        filtered_df = df[df["Status"].str.upper() == "ALERT"]
    else:
        filtered_df = df[df["Status"].str.upper() == filt_status]

    # Show latest events
    st.dataframe(filtered_df, use_container_width=True)

    # Breach summary is always based on ALERT (breach) events
    breach_df = df[df["Status"].str.upper() == "ALERT"]
    if not breach_df.empty:
        st.error(f"⚠ Total breaches (ALERT events): {len(breach_df)}")
    else:
        st.success("No breaches detected.")
