from scapy.all import sniff, IP, TCP, UDP, get_if_list
from datetime import datetime
import csv
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))
from utils.config import NETWORK_INTERFACE, PACKET_FILTER, PACKET_LIMIT, ENHANCED_PACKETS_PATH
from utils.logger import log_info, log_error

packet_data = []


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
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            ttl = packet[IP].ttl
            length = len(packet)
            flags = str(packet[IP].flags)  # e.g., DF, MF

            # Default values
            src_port = dst_port = 'N/A'
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Log & store
            log_info(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Proto: {proto} | TTL: {ttl} | Len: {length} | Flags: {flags}")
            print(f"[{timestamp}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | Proto: {proto} | TTL: {ttl} | Len: {length} | Flags: {flags}")
            packet_data.append([
                timestamp, src_ip, dst_ip, src_port, dst_port,
                proto, ttl, length, flags
            ])
    except Exception as e:
        log_error(f"Error processing packet: {e}")


def main():
    """Main function to capture enhanced packet data."""
    log_info("Starting enhanced packet capture...")
    
    iface = get_network_interface()
    if not iface:
        log_error("No network interface available. Exiting.")
        sys.exit(1)
    
    log_info(f"Using network interface: {iface}")
    log_info(f"Packet filter: {PACKET_FILTER}")
    log_info(f"Packet limit: {PACKET_LIMIT}")
    log_info("🚀 Capturing enhanced packet data (Press Ctrl+C to stop)...")
    
    try:
        sniff(iface=iface, prn=packet_callback, filter=PACKET_FILTER, 
              store=False, count=PACKET_LIMIT + 1)
        
        # Save to CSV
        log_info(f"Saving captured packets to: {ENHANCED_PACKETS_PATH}")
        with open(ENHANCED_PACKETS_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Source IP", "Destination IP", "Source Port",
                "Destination Port", "Protocol", "TTL", "Length", "Flags"
            ])
            writer.writerows(packet_data)
        
        log_info(f"Successfully captured and saved {len(packet_data)} packets")
        
    except KeyboardInterrupt:
        log_info("Packet capture stopped by user")
        if packet_data:
            log_info(f"Saving {len(packet_data)} captured packets...")
            with open(ENHANCED_PACKETS_PATH, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "Source IP", "Destination IP", "Source Port",
                    "Destination Port", "Protocol", "TTL", "Length", "Flags"
                ])
                writer.writerows(packet_data)
            log_info(f"Saved to: {ENHANCED_PACKETS_PATH}")
    except PermissionError:
        log_error("Permission denied. Please run with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error during packet capture: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
