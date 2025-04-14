from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from datetime import datetime


model = joblib.load("logistic_model.pkl")
scaler = joblib.load("scaler.pkl")


feature_columns = ['Source Port', 'Destination Port', 'TTL', 'Length', 'Flags']

# we are extracking Feature from live packets
def extract_features(packet):
    if IP in packet:
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        ttl = packet[IP].ttl
        length = len(packet)
        flags_str = packet[IP].flags
        flags_numeric = 1 if 'DF' in flags_str else 0  # Convert live flags to 0 or 1

        return pd.DataFrame([[src_port, dst_port, ttl, length, flags_numeric]], columns=feature_columns)
    return None

# It is Callback function for each sniffed packet
def detect_packet(packet):
    features_df = extract_features(packet)
    if features_df is not None:
        features_scaled = scaler.transform(features_df)
        prediction = model.predict(features_scaled)[0]

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        label = "Malicious 🚨" if prediction == 0 else "Normal ✅"
        features_list = features_df.values.flatten().tolist()
        print(f"[{timestamp}] Prediction: {label} | Features: {features_list}")

# now we sniff the live packets
try:
    sniff(filter="ip", prn=detect_packet, store=False, iface=r"\Device\NPF_{4E1A6BE1-14F5-4C56-BD5F-456FF3A8D748}")
except Exception as e:
    print(f"Error during sniffing: {e}")
    print("Make sure you have the correct interface name and necessary permissions.")