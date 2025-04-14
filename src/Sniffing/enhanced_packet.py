from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv

iface = r"\Device\NPF_{4E1A6BE1-14F5-4C56-BD5F-456FF3A8D748}"

packet_data = []

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        length = len(packet)
        flags = packet[IP].flags  # e.g., DF, MF

        # Default values
        src_port = dst_port = 'N/A'
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Log & store
        print(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Proto: {proto} | TTL: {ttl} | Len: {length} | Flags: {flags}")
        packet_data.append([
            timestamp, src_ip, dst_ip, src_port, dst_port,
            proto, ttl, length, flags
        ])

print("🚀 Capturing enhanced packet data (Press Ctrl+C to stop)...")
sniff(iface=iface, prn=packet_callback, filter="ip", store=False, count=51)

# Save to CSV
with open("enhanced_packets.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Timestamp", "Source IP", "Destination IP", "Source Port",
        "Destination Port", "Protocol", "TTL", "Length", "Flags"
    ])
    writer.writerows(packet_data)
