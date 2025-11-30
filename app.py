"""
Network Intrusion Detection System (NIDS) Dashboard
Red Team vs. Blue Team Simulator
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import threading
import time
import joblib
from scapy.all import IP, TCP, send, sr1
import socket
from collections import deque
import plotly.graph_objects as go
import plotly.express as px

# Page Configuration
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cybersecurity Dark Theme
st.markdown("""
<style>
    .main {
        background-color: #0a0e27;
        color: #00ff41;
    }

    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
    }

    div[data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: bold;
    }

    /* Target the Metric LABEL (The text above numbers) */
    /* CHANGE: Removed 'div' to match any tag (label, div, etc.) */
    [data-testid="stMetricLabel"] {
        font-size: 1.5rem !important;
        font-weight: bold;
   
    }

    /* ADDED: Explicitly target paragraph tags inside the label if Streamlit nests them */
    [data-testid="stMetricLabel"] p {
        font-size: 1.5rem !important;
        font-weight: bold;

    }

    .metric-card {
        background: linear-gradient(135deg, #1e2139 0%, #2a2f4a 100%);
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    }

    .safe-metric {
        color: #00ff41 !important;
    }

    .threat-metric {
        color: #ff3131 !important;
    }

    .attack-btn {
        background: linear-gradient(135deg, #ff3131 0%, #ff6b6b 100%);
        color: white;
        border: none;
        padding: 10px;
        border-radius: 5px;
        font-weight: bold;
    }

    .benign-btn {
        background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%);
        color: black;
        border: none;
        padding: 10px;
        border-radius: 5px;
        font-weight: bold;
    }

    h1, h2, h3 {
        color: #00ff41;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    }

    .dataframe {
        background-color: #1e2139 !important;
        color: #00ff41 !important;
    }

    .alert-box {
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
        animation: pulse 2s infinite;
    }

    .alert-danger {
        background-color: rgba(255, 49, 49, 0.2);
        border-left: 4px solid #ff3131;
    }

    .alert-success {
        background-color: rgba(0, 255, 65, 0.2);
        border-left: 4px solid #00ff41;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if 'traffic_log' not in st.session_state:
    st.session_state.traffic_log = []
if 'total_flows' not in st.session_state:
    st.session_state.total_flows = 0
if 'threats_detected' not in st.session_state:
    st.session_state.threats_detected = 0
if 'safe_traffic' not in st.session_state:
    st.session_state.safe_traffic = 0
if 'sniffer_running' not in st.session_state:
    st.session_state.sniffer_running = False
if 'attack_timeline' not in st.session_state:
    st.session_state.attack_timeline = deque(maxlen=60)  # Last 60 seconds
if 'recent_alerts' not in st.session_state:
    st.session_state.recent_alerts = deque(maxlen=10)
if 'csv_data' not in st.session_state:
    st.session_state.csv_data = None
if 'benign_rows' not in st.session_state:
    st.session_state.benign_rows = None
if 'dos_rows' not in st.session_state:
    st.session_state.dos_rows = None
if 'portscan_rows' not in st.session_state:
    st.session_state.portscan_rows = None
if 'bot_rows' not in st.session_state:
    st.session_state.bot_rows = None
if 'brute_force_rows' not in st.session_state:
    st.session_state.brute_force_rows = None
if 'infiltration_rows' not in st.session_state:
    st.session_state.infiltration_rows = None
if 'web_attack_rows' not in st.session_state:
    st.session_state.web_attack_rows = None

# Expected 26 Features for the Model
EXPECTED_FEATURES = [
    'Destination Port', 'Init_Win_bytes_backward', 'Bwd Header Length',
    'Init_Win_bytes_forward', 'Packet Length Mean', 'Fwd IAT Min',
    'Fwd Packet Length Max', 'Packet Length Variance', 'URG Flag Count',
    'Fwd Header Length', 'Bwd IAT Max', 'Flow IAT Min', 'min_seg_size_forward',
    'PSH Flag Count', 'Bwd Packet Length Max', 'Flow Duration', 'Flow Bytes/s',
    'Flow IAT Std', 'Fwd IAT Mean', 'Fwd Packet Length Mean', 'Flow IAT Max',
    'Bwd IAT Mean', 'Max Packet Length', 'Bwd Packet Length Min',
    'Total Fwd Packets', 'Fwd IAT Std'
]

# Load ML Model
@st.cache_resource
def load_model():
    try:
        model = joblib.load('Models/random_forest_nids.pkl')
        return model
    except Exception as e:
        # Placeholder for when model isn't found to prevent crash on first run
        return None

model = load_model()

# Load CSV Data
@st.cache_data
def load_csv_data(csv_path='network_data.csv'):
    """Load and prepare CSV data with labeled network flows"""
    try:
        df = pd.read_csv(csv_path)

        # Identify the label column (common names)
        label_col = None
        for col in df.columns:
            if col.lower() in ['label', 'attack', 'class', 'type', 'attack_type']:
                label_col = col
                break

        if label_col is None:
            st.error("Could not find label column in CSV. Please ensure your CSV has a column named 'Label', 'Attack', 'Class', or 'Type'")
            return None, None, None, None, None, None, None, None

        # Separate data by attack type
        benign_data = df[df[label_col].str.lower().str.contains('benign', na=False)]
        dos_data = df[df[label_col].str.lower().str.contains('dos', na=False)]
        portscan_data = df[df[label_col].str.lower().str.contains('portscan|port', na=False)]
        bot_data = df[df[label_col].str.lower().str.contains('bot', na=False)]
        brute_force_data = df[df[label_col].str.lower().str.contains('brute', na=False)]
        infiltration_data = df[df[label_col].str.lower().str.contains('infiltration', na=False)]
        web_attack_data = df[df[label_col].str.lower().str.contains('web', na=False)]

        return df, benign_data, dos_data, portscan_data, bot_data, brute_force_data, infiltration_data, web_attack_data
    except FileNotFoundError:
        # Fail silently here, user will be prompted to upload
        return None, None, None, None, None, None, None, None
    except Exception as e:
        st.error(f"Error loading CSV: {e}")
        return None, None, None, None, None, None, None, None

# Initialize CSV data
if st.session_state.csv_data is None:
    csv_data, benign_rows, dos_rows, portscan_rows, bot_rows, brute_force_rows, infiltration_rows, web_attack_rows = load_csv_data()
    st.session_state.csv_data = csv_data
    st.session_state.benign_rows = benign_rows
    st.session_state.dos_rows = dos_rows
    st.session_state.portscan_rows = portscan_rows
    st.session_state.bot_rows = bot_rows
    st.session_state.brute_force_rows = brute_force_rows
    st.session_state.infiltration_rows = infiltration_rows
    st.session_state.web_attack_rows = web_attack_rows

def get_random_row_from_csv(attack_type=None):
    """Get a random row from CSV data based on attack type"""
    if st.session_state.csv_data is None:
        st.error("No CSV data loaded")
        return None

    if attack_type == "DoS" and st.session_state.dos_rows is not None and len(st.session_state.dos_rows) > 0:
        row = st.session_state.dos_rows.sample(n=1).iloc[0]
    elif attack_type == "PortScan" and st.session_state.portscan_rows is not None and len(st.session_state.portscan_rows) > 0:
        row = st.session_state.portscan_rows.sample(n=1).iloc[0]
    elif attack_type == "Bot" and st.session_state.bot_rows is not None and len(st.session_state.bot_rows) > 0:
        row = st.session_state.bot_rows.sample(n=1).iloc[0]
    elif attack_type == "Brute Force" and st.session_state.brute_force_rows is not None and len(st.session_state.brute_force_rows) > 0:
        row = st.session_state.brute_force_rows.sample(n=1).iloc[0]
    elif attack_type == "Infiltration" and st.session_state.infiltration_rows is not None and len(st.session_state.infiltration_rows) > 0:
        row = st.session_state.infiltration_rows.sample(n=1).iloc[0]
    elif attack_type == "Web Attack" and st.session_state.web_attack_rows is not None and len(st.session_state.web_attack_rows) > 0:
        row = st.session_state.web_attack_rows.sample(n=1).iloc[0]
    elif st.session_state.benign_rows is not None and len(st.session_state.benign_rows) > 0:
        row = st.session_state.benign_rows.sample(n=1).iloc[0]
    else:
        row = st.session_state.csv_data.sample(n=1).iloc[0]

    return row

def extract_features_from_row(row):
    """Extract the 26 required features from a CSV row"""
    flow_data = {}

    for feature in EXPECTED_FEATURES:
        if feature in row.index:
            flow_data[feature] = row[feature]
        else:
            flow_data[feature] = 0

    return flow_data

def predict_flow(flow_data):
    """Predict if flow is malicious using the ML model"""
    if model is None:
        return "Unknown"

    df = pd.DataFrame([flow_data])

    # Ensure all expected features are present
    for feature in EXPECTED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0

    # Select only the expected features in the correct order
    df = df[EXPECTED_FEATURES]

    try:
        prediction = model.predict(df)[0]

        # Map numeric predictions to labels based on your model's classes
        prediction_map = {
            0: "BENIGN",
            1: "Bot",
            2: "Brute Force",
            3: "DoS",
            4: "Infiltration",
            5: "PortScan",
            6: "Web Attack"
        }

        # Convert to string if numeric
        if isinstance(prediction, (int, np.integer)):
            return prediction_map.get(int(prediction), f"Class_{prediction}")

        return str(prediction)
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return "Unknown"

def add_traffic_entry(dst_port, prediction, status, row=None):
    """Add entry to traffic log"""
    entry = {
        'Timestamp': datetime.now().strftime('%H:%M:%S'),
        'Dest Port': dst_port,
        'Prediction': prediction,
        'Status': status,
        'Flow Duration': row.get('Flow Duration') if row is not None else None,

    }

    st.session_state.traffic_log.insert(0, entry)
    if len(st.session_state.traffic_log) > 100:
        st.session_state.traffic_log.pop()

    st.session_state.total_flows += 1
    if status == 'Malicious':
        st.session_state.threats_detected += 1
        st.session_state.recent_alerts.appendleft({
            'time': entry['Timestamp'],
            'type': prediction,
            
            'port': dst_port
        })
    else:
        st.session_state.safe_traffic += 1

    # Update attack timeline
    current_minute = datetime.now().strftime('%H:%M')
    if st.session_state.attack_timeline and st.session_state.attack_timeline[-1]['time'] == current_minute:
        if status == 'Malicious':
            st.session_state.attack_timeline[-1]['attacks'] += 1
    else:
        st.session_state.attack_timeline.append({
            'time': current_minute,
            'attacks': 1 if status == 'Malicious' else 0
        })

# Red Team Attack Functions
def is_malicious(prediction):
    """Determine if prediction is malicious"""
    pred_str = str(prediction).lower()
    return pred_str != "benign"

def send_benign_traffic():
    """Send benign traffic from CSV data"""
    try:
        row = get_random_row_from_csv("Benign")
        if row is None:
            return False

        flow = extract_features_from_row(row)
        prediction = predict_flow(flow)
        status = 'Malicious' if is_malicious(prediction) else 'Safe'

        src_ip = row.get('Source IP')  # No fallback
        dst_port = int(flow.get('Destination Port', 80))

        add_traffic_entry(dst_port, prediction, status, row=row)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def launch_dos_attack():
    """Launch DoS attack using real CSV data"""
    try:
        for _ in range(10):
            row = get_random_row_from_csv("DoS")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', 80))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.05)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def run_port_scan():
    """Run port scan using real CSV data"""
    try:
        for _ in range(7):
            row = get_random_row_from_csv("PortScan")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', 22))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.1)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def launch_bot_attack():
    """Launch Bot attack using real CSV data"""
    try:
        for _ in range(8):
            row = get_random_row_from_csv("Bot")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', "N/A"))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.07)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def launch_brute_force_attack():
    """Launch Brute Force attack using real CSV data"""
    try:
        for _ in range(5):
            row = get_random_row_from_csv("Brute Force")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', 22))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.2)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False
def launch_infiltration_attack():
    """Launch Infiltration attack using real CSV data"""
    try:
        for _ in range(6):
            row = get_random_row_from_csv("Infiltration")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', 80))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.1)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

def launch_web_attack():
    """Launch Web Attack using real CSV data"""
    try:
        for _ in range(4):
            row = get_random_row_from_csv("Web Attack")
            if row is None:
                return False

            flow = extract_features_from_row(row)
            prediction = predict_flow(flow)
            status = 'Malicious' if is_malicious(prediction) else 'Safe'

            src_ip = row.get('Source IP')  # No fallback
            dst_port = int(flow.get('Destination Port', 80))

            add_traffic_entry(dst_port, prediction, status, row=row)
            time.sleep(0.15)
        return True
    except Exception as e:
        st.error(f"Error: {e}")
        return False

# Main Dashboard Layout
st.title("🛡️ Network Intrusion Detection System")
st.markdown("### Real-Time Threat Monitoring & Analysis")

# Sidebar - Red Team Attack Simulator
with st.sidebar:
    st.markdown("## 📁 Data Upload")
    uploaded_file = st.file_uploader("Upload CSV (optional)", type=['csv'])
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            label_col = None
            for col in df.columns:
                if col.lower() in ['label', 'attack', 'class', 'type', 'attack_type']:
                    label_col = col
                    break

            if label_col:
                st.session_state.csv_data = df
                st.session_state.benign_rows = df[df[label_col].str.lower().str.contains('benign', na=False)]
                st.session_state.dos_rows = df[df[label_col].str.lower().str.contains('dos', na=False)]
                st.session_state.portscan_rows = df[df[label_col].str.lower().str.contains('portscan|port', na=False)]
                st.session_state.bot_rows = df[df[label_col].str.lower().str.contains('bot', na=False)]
                st.session_state.brute_force_rows = df[df[label_col].str.lower().str.contains('brute', na=False)]
                st.session_state.infiltration_rows = df[df[label_col].str.lower().str.contains('infiltration', na=False)]
                st.session_state.web_attack_rows = df[df[label_col].str.lower().str.contains('web', na=False)]
                st.success("CSV uploaded successfully!")
            else:
                st.error("Label column not found in CSV")
        except Exception as e:
            st.error(f"Error uploading CSV: {e}")

    st.markdown("---")
    st.markdown("## 🚀 Attack Simulator")
    st.markdown("### Red Team Operations")
    st.markdown("---")

    if st.button("🟢 Send Benign Traffic", use_container_width=True):
        with st.spinner("Sending benign traffic..."):
            if send_benign_traffic():
                st.success("✓ Benign traffic sent")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🔴 Launch DoS Attack", use_container_width=True):
        with st.spinner("Launching DoS attack..."):
            if launch_dos_attack():
                st.warning("⚠️ DoS attack simulated!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🔍 Run Port Scan", use_container_width=True):
        with st.spinner("Scanning ports..."):
            if run_port_scan():
                st.warning("⚠️ Port scan completed!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🤖 Launch Bot Attack", use_container_width=True):
        with st.spinner("Launching Bot attack..."):
            if launch_bot_attack():
                st.warning("⚠️ Bot attack simulated!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🔓 Launch Brute Force Attack", use_container_width=True):
        with st.spinner("Launching Brute Force attack..."):
            if launch_brute_force_attack():
                st.warning("⚠️ Brute Force attack simulated!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🕵️ Launch Infiltration Attack", use_container_width=True):
        with st.spinner("Launching Infiltration attack..."):
            if launch_infiltration_attack():
                st.warning("⚠️ Infiltration attack simulated!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("🌐 Launch Web Attack", use_container_width=True):
        with st.spinner("Launching Web attack..."):
            if launch_web_attack():
                st.warning("⚠️ Web attack simulated!")
                time.sleep(0.5)
                st.rerun()

    st.markdown("---")
    st.markdown("### 📊 System Status")
    if model is not None:
        st.success("🟢 ML Model: Active")
    else:
        st.error("🔴 ML Model: Offline")

    if st.session_state.csv_data is not None:
        st.success("🟢 CSV Data: Loaded")
        if st.session_state.benign_rows is not None:
            st.info(f"Benign rows: {len(st.session_state.benign_rows)}")
        if st.session_state.dos_rows is not None:
            st.info(f"DoS rows: {len(st.session_state.dos_rows)}")
        if st.session_state.portscan_rows is not None:
            st.info(f"PortScan rows: {len(st.session_state.portscan_rows)}")
        if st.session_state.bot_rows is not None:
            st.info(f"Bot rows: {len(st.session_state.bot_rows)}")
        if st.session_state.brute_force_rows is not None:
            st.info(f"Brute Force rows: {len(st.session_state.brute_force_rows)}")
        if st.session_state.infiltration_rows is not None:
            st.info(f"Infiltration rows: {len(st.session_state.infiltration_rows)}")
        if st.session_state.web_attack_rows is not None:
            st.info(f"Web Attack rows: {len(st.session_state.web_attack_rows)}")
    else:
        st.error("🔴 CSV Data: Not Found")
        st.warning("Place 'network_data.csv' in the project directory")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔄 Reset Dashboard", use_container_width=True):
        st.session_state.traffic_log = []
        st.session_state.total_flows = 0
        st.session_state.threats_detected = 0
        st.session_state.safe_traffic = 0
        st.session_state.attack_timeline = deque(maxlen=60)
        st.session_state.recent_alerts = deque(maxlen=10)
        st.rerun()

# Top Metrics Row
col1, col2, col3 = st.columns(3)

with col1:
    
    st.metric(
        label="📦 Total Flows Captured",
        value=st.session_state.total_flows,
        delta=None
    )
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    
    threat_delta = st.session_state.threats_detected
    st.metric(
        label="🚨 Threats Detected",
        value=st.session_state.threats_detected,
        delta=f"{threat_delta} alerts" if threat_delta > 0 else None,
        delta_color="inverse"
    )
    st.markdown("</div>", unsafe_allow_html=True)

with col3:
    
    st.metric(
        label="✅ Safe Traffic",
        value=st.session_state.safe_traffic,
        delta=None
    )
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("---")

# Main Content Area
col_left, col_right = st.columns([2, 1])

with col_left:
    st.markdown("### 📡 Live Traffic Monitor")

    if st.session_state.traffic_log:
        df = pd.DataFrame(st.session_state.traffic_log)

        # Color code the status column
        def color_status(val):
            color = '#ff3131' if val == 'Malicious' else '#00ff41'
            return f'color: {color}; font-weight: bold'

        styled_df = df.style.applymap(color_status, subset=['Status'])
        st.dataframe(styled_df, use_container_width=True, height=600)  # Increased height for longer table
    else:
        st.info("🔵 Waiting for network traffic... Use the Attack Simulator to generate traffic.")

with col_right:
    st.markdown("### 🚨 Recent Alerts")

    if st.session_state.recent_alerts:
        for alert in list(st.session_state.recent_alerts)[:5]:
            st.markdown(f"""
            <div class='alert-box alert-danger'>
                <strong>🔴 {alert['type']}</strong><br>
                Time: {alert['time']}<br>
                Destination:{alert['port']}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class='alert-box alert-success'>
            <strong>🟢 All Clear</strong><br>
            No threats detected
        </div>
        """, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #00ff41; opacity: 0.7;'>
    🛡️ NIDS Dashboard | Blue Team Defense System | Real-Time Threat Detection
</div>
""", unsafe_allow_html=True)

# Auto-refresh every 2 seconds when there's activity
if st.session_state.total_flows > 0:
    time.sleep(2)
    st.rerun()