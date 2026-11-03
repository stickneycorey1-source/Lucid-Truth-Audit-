import sqlite3
import pandas as pd
import streamlit as st
import os

# Page Config
st.set_page_config(
    page_title="Lucid-Truth-Audit CISO Telemetry",
    page_icon="🛡️",
    layout="wide"
)

DB_PATH = os.getenv("AUDIT_DB_PATH", "lucid_audit.db")

@st.cache_data(ttl=5)
def load_audit_data():
    """Loads audit logs from the persistent SQLite ledger."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(columns=["id", "timestamp", "client_ip", "endpoint", "threat_detected", "violation_type", "masked_payload"])
    
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC", conn)
    conn.close()
    return df

# Header
st.title("🛡️ Lucid-Truth-Audit: CISO Telemetry & Compliance Ledger")
st.markdown("**The Stickney Audit Mandate** — Real-time edge threat interception, PII masking, and token-cost protection.")

# Load Data
df = load_audit_data()

# Top-Level Metrics Bar
col1, col2, col3, col4 = st.columns(4)

total_requests = len(df)
threats_blocked = len(df[df["threat_detected"] == 1]) if not df.empty else 0
clean_requests = total_requests - threats_blocked
estimated_tokens_saved = threats_blocked * 1250  # Average token burn saved per intercepted attack

with col1:
    st.metric(label="Total Gateway Requests", value=total_requests)
with col2:
    st.metric(label="Threats / PII Blocked (403)", value=threats_blocked, delta=f"{threats_blocked} attacks neutralized")
with col3:
    st.metric(label="Clean Verified Traffic", value=clean_requests)
with col4:
    st.metric(label="Est. LLM Tokens Saved", value=f"{estimated_tokens_saved:,}", delta="$0.00 Burned")

st.divider()

# Charts & Breakdown Section
if not df.empty:
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("📊 Violations by Type")
        if "violation_type" in df.columns:
            violation_counts = df["violation_type"].value_counts()
            st.bar_chart(violation_counts)

    with col_right:
        st.subheader("⚡ Gateway Traffic Status")
        status_counts = df["threat_detected"].map({0: "Approved (200)", 1: "Blocked (403)"}).value_counts()
        st.altair_chart(
            pd.DataFrame({"Status": status_counts.index, "Count": status_counts.values}),
            use_container_width=True
        )

    st.divider()

    # Raw Audit Ledger Table
    st.subheader("📋 Tamper-Evident SQLite Threat Ledger (`lucid_audit.db`)")
    st.markdown("Showing live logs recorded by the FastAPI edge middleware.")
    
    # Style table view
    st.dataframe(df, use_container_width=True)

else:
    st.info("No audit logs found yet in `lucid_audit.db`. Send a test request to your FastAPI gateway to populate telemetry!")

# Sidebar Controls
st.sidebar.header("Gateway Controls")
if st.sidebar.button("🔄 Refresh Telemetry"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Environment:** Production / Edge")
st.sidebar.markdown("**Database:** SQLite (`lucid_audit.db`)")
