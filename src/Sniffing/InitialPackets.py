from scapy.all import sniff, IP, get_if_list
from datetime import datetime
import csv
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))
from utils.config import NETWORK_INTERFACE, PACKET_FILTER, PACKET_LIMIT, CAPTURED_PACKETS_PATH
from utils.logger import log_info, log_error

captured_packets = []


def get_network_interface():
    """Get network interface from config or detect automatically."""
    if NETWORK_INTERFACE:
        return NETWORK_INTERFACE
    
    # Try to auto-detect interface
    interfaces = get_if_list()
    if interfaces:
        log_info(f"Available interfaces: {interfaces}")
        # Prefer Ethernet interfaces
        for iface in interfaces:
            if 'eth' in iface.lower() or 'en' in iface.lower():
                log_info(f"Auto-selected interface: {iface}")
                return iface
        # Fallback to first available
        if interfaces:
            log_info(f"Using first available interface: {interfaces[0]}")
            return interfaces[0]
    
    log_error("No network interface found. Please set NETWORK_INTERFACE in config.py")
    return None


def packet_callback(packet):
    """Callback function to process each captured packet."""
    try:
        if IP in packet:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            ttl = packet[IP].ttl
            length = len(packet)
            
            log_info(f"[{timestamp}] {src} → {dst} | Proto: {proto} | TTL: {ttl} | Len: {length}")
            print(f"[{timestamp}] {src} → {dst} | Proto: {proto} | TTL: {ttl} | Len: {length}")
            captured_packets.append([timestamp, src, dst, proto, ttl, length])
    except Exception as e:
        log_error(f"Error processing packet: {e}")


def main():
    """Main function to capture initial packets."""
    log_info("Starting initial packet capture...")
    
    iface = get_network_interface()
    if not iface:
        log_error("No network interface available. Exiting.")
        sys.exit(1)
    
    log_info(f"Using network interface: {iface}")
    log_info(f"Packet filter: {PACKET_FILTER}")
    log_info(f"Packet limit: {PACKET_LIMIT}")
    
    try:
        # Start sniffing
        sniff(iface=iface, prn=packet_callback, filter=PACKET_FILTER, 
              store=False, count=PACKET_LIMIT)
        
        # Save to CSV
        log_info(f"Saving captured packets to: {CAPTURED_PACKETS_PATH}")
        with open(CAPTURED_PACKETS_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "TTL", "Length"])
            writer.writerows(captured_packets)
        
        log_info(f"Successfully captured and saved {len(captured_packets)} packets")
        
    except KeyboardInterrupt:
        log_info("Packet capture stopped by user")
        if captured_packets:
            log_info(f"Saving {len(captured_packets)} captured packets...")
            with open(CAPTURED_PACKETS_PATH, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "TTL", "Length"])
                writer.writerows(captured_packets)
            log_info(f"Saved to: {CAPTURED_PACKETS_PATH}")
    except PermissionError:
        log_error("Permission denied. Please run with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error during packet capture: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
