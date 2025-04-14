from scapy.all import sniff, IP
from datetime import datetime

# iface = r"\Device\NPF_{4E1A6BE1-14F5-4C56-BD5F-456FF3A8D748}"  # Replace if needed

# def packet_callback(packet):
#     if IP in packet:
#         timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         print(f"[{timestamp}] {packet[IP].src} → {packet[IP].dst} | Proto: {packet[IP].proto} | TTL: {packet[IP].ttl} | Len: {len(packet)}")

# sniff(iface=iface, prn=packet_callback, filter="ip", store=False, count=10)


import csv
iface = r"\Device\NPF_{4E1A6BE1-14F5-4C56-BD5F-456FF3A8D748}" 
captured_packets = []

def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        length = len(packet)
        print(f"[{timestamp}] {src} → {dst} | Proto: {proto} | TTL: {ttl} | Len: {length}")
        captured_packets.append([timestamp, src, dst, proto, ttl, length])

# Start sniffing
sniff(iface=iface, prn=packet_callback, filter="ip", store=False, count=50)

# Save to CSV
with open("captured_packets.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "TTL", "Length"])
    writer.writerows(captured_packets)
