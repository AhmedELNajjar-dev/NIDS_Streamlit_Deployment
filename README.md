# 🛡️ Network Intrusion Detection System (NIDS) Dashboard

A professional, futuristic cybersecurity dashboard for real-time network intrusion detection with Red Team vs. Blue Team simulation capabilities.

## Features

### 🔴 Red Team (Attack Simulator)
- **Benign Traffic Generator**: Simulates normal HTTP traffic
- **DoS Attack Launcher**: Simulates Denial of Service attacks with rapid packet transmission
- **Port Scanner**: Scans common ports (20, 21, 22, 23, 25, 80, 443)

### 🔵 Blue Team (Defense Dashboard)
- **Real-time Metrics**: Total flows, threats detected, safe traffic
- **Live Traffic Monitor**: Real-time traffic log with color-coded threat levels
- **Alert System**: Recent alerts panel showing detected threats
- **Attack Timeline**: Visual chart showing attacks per minute
- **ML-Powered Detection**: Random Forest model for threat classification

## Installation

1. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

2. **Place Your Model**:
   - Put your trained `random_forest_nids.pkl` file in the `Models/` directory
   - The model should accept the 26 features specified in the code

3. **Run the Application**:
```bash
streamlit run app.py
```

## Model Requirements

The Random Forest model must be trained to accept these 26 features in order:
- Destination Port
- Init_Win_bytes_backward
- Bwd Header Length
- Init_Win_bytes_forward
- Packet Length Mean
- Fwd IAT Min
- Fwd Packet Length Max
- Packet Length Variance
- URG Flag Count
- Fwd Header Length
- Bwd IAT Max
- Flow IAT Min
- min_seg_size_forward
- PSH Flag Count
- Bwd Packet Length Max
- Flow Duration
- Flow Bytes/s
- Flow IAT Std
- Fwd IAT Mean
- Fwd Packet Length Mean
- Flow IAT Max
- Bwd IAT Mean
- Max Packet Length
- Bwd Packet Length Min
- Total Fwd Packets
- Fwd IAT Std

## Usage

1. **Launch the Dashboard**: Run `streamlit run app.py`
2. **Simulate Attacks**: Use the left sidebar buttons to generate traffic
3. **Monitor Threats**: Watch the main dashboard for real-time detection
4. **Review Timeline**: Check the attack timeline chart for patterns
5. **Reset Dashboard**: Clear all data using the Reset button

## Design Features

- **Dark Cybersecurity Theme**: Professional dark mode with green/red indicators
- **Real-time Updates**: Auto-refreshing dashboard every 2 seconds
- **Responsive Metrics**: Large cards showing key statistics
- **Alert Animations**: Pulsing alerts for detected threats
- **Color-coded Status**: Green for safe, red for malicious

## Technical Architecture

- **Threading**: Background packet simulation without UI freezing
- **Session State**: Persistent log storage across interactions
- **Plotly Charts**: Interactive timeline visualizations
- **Simulated Flows**: Realistic network flow generation for demonstration

## Notes

- The application simulates network flows for demonstration purposes
- For production use with real traffic, integrate with CICFlowMeter and actual network interfaces
- Model predictions are based on the loaded Random Forest classifier
- All attack simulations are safe and run locally

## Security

This is a defensive security tool for education and demonstration. All simulated attacks are local and pose no threat to any network.
