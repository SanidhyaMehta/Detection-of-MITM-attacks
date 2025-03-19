from scapy.all import sniff, IP
import pandas as pd
from datetime import datetime

# Initialize an empty list to store packet data
packet_log = []

def packet_callback(packet):
    if IP in packet:
        packet_log.append({
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source": packet[IP].src,
            "Destination": packet[IP].dst,
            "Protocol": packet[IP].proto,
            "Packet Summary": str(packet.summary())
        })
        print(packet.summary())  # Display live packet info

# Capture packets and log them
try:
    print("Starting packet capture (50 packets)...")
    sniff(prn=packet_callback, count = 50)
except Exception as e:
    print(f"Error during packet capture: {e}")

# Save to CSV for later analysis
if packet_log:
    df = pd.DataFrame(packet_log)
    df.to_csv("network_log.csv", index = False)
    print("Packet data saved to network_log.csv")
else:
    print("No packets captured.")




