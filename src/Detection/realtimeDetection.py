from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from datetime import datetime
import os

# Get the base directory (parent of /src)
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Load models from the base Detection-of-MITM-attacks directory
model_path = os.path.join(base_dir, "logistic_model.pkl")
scaler_path = os.path.join(base_dir, "scaler.pkl")


model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

print("Loading model from:", model_path)
print("Loading scaler from:", scaler_path)



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
        label = "Malicious" if prediction == 0 else "Normal"
        features_list = features_df.values.flatten().tolist()
        print(f"[{timestamp}] Prediction: {label} | Features: {features_list}")

# now we sniff the live packets
try:
    sniff(filter="ip", prn=detect_packet, store=False, iface="en0")
except Exception as e:
    print(f"Error during sniffing: {e}")
    print("Make sure you have the correct interface name and necessary permissions.")