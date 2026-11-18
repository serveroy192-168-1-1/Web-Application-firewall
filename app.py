"""
Streamlit Security Monitoring Dashboard for WAF.
Reads real-time attack events from data/waf_logs.db and visualizes trends,
breakdowns, and inspection latencies.
"""

import os
import sqlite3
import pandas as pd
import streamlit as st

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "waf_logs.db")

st.set_page_config(
    page_title="WAF Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Web Application Firewall — Security Monitoring Dashboard")
st.markdown("Real-time telemetry, machine learning anomaly detection scores, and attack classification.")


def load_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM waf_logs ORDER BY id DESC", conn)
    conn.close()
    return df


df = load_data()

# Metric summary cards
col1, col2, col3, col4 = st.columns(4)

if df.empty:
    st.info("No WAF events logged yet. Start the WAF proxy or execute test attacks to populate data.")
else:
    total_requests = len(df)
    blocked_requests = len(df[df["action"] == "blocked"])
    allowed_requests = total_requests - blocked_requests
    avg_latency = df["latency_ms"].mean() if "latency_ms" in df else 0.0

    col1.metric("Total Inbound Requests", total_requests)
    col2.metric("Blocked Attacks (403)", blocked_requests, f"{(blocked_requests / total_requests) * 100:.1f}%")
    col3.metric("Allowed Requests", allowed_requests)
    col4.metric("Average WAF Latency", f"{avg_latency:.2f} ms")

    st.divider()

    # Visualizations
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Attack Type Breakdown")
        attack_counts = df[df["action"] == "blocked"]["attack_type"].value_counts()
        if not attack_counts.empty:
            st.bar_chart(attack_counts)
        else:
            st.write("No attacks blocked yet.")

    with chart_col2:
        st.subheader("Detection Source Distribution")
        source_counts = df["detection_source"].value_counts()
        st.bar_chart(source_counts)

    st.divider()

    # Recent Event Log Table
    st.subheader("Recent Request Logs")
    st.dataframe(
        df[["id", "timestamp", "src_ip", "method", "path", "attack_type", "detection_source", "ml_score", "action", "latency_ms", "reason"]],
        use_container_width=True
    )
