from scapy.all import sniff, IP, TCP, UDP, get_if_list
import pandas as pd
import joblib
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))
from utils.config import MODEL_PATH, SCALER_PATH, FEATURE_COLUMNS, NETWORK_INTERFACE, PACKET_FILTER
from utils.logger import log_info, log_error

# Global variables for model and scaler
model = None
scaler = None


def load_models():
    """Load the trained model and scaler with error handling."""
    global model, scaler
    try:
        if not MODEL_PATH.exists():
            log_error(f"Model file not found: {MODEL_PATH}")
            log_error("Please train the model first using: python src/ML_Model/Traning.py")
            return False
        
        if not SCALER_PATH.exists():
            log_error(f"Scaler file not found: {SCALER_PATH}")
            log_error("Please train the model first using: python src/ML_Model/Traning.py")
            return False
        
        log_info(f"Loading model from: {MODEL_PATH}")
        model = joblib.load(MODEL_PATH)
        
        log_info(f"Loading scaler from: {SCALER_PATH}")
        scaler = joblib.load(SCALER_PATH)
        
        log_info("Models loaded successfully")
        return True
    except Exception as e:
        log_error(f"Error loading models: {e}")
        return False


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


def extract_features(packet):
    """Extract features from live packets."""
    try:
        if IP not in packet:
            return None
        
        
        src_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
        elif UDP in packet:
            src_port = packet[UDP].sport
        
        dst_port = 0
        if TCP in packet:
            dst_port = packet[TCP].dport
        elif UDP in packet:
            dst_port = packet[UDP].dport
        
        ttl = packet[IP].ttl
        length = len(packet)
        flags_str = str(packet[IP].flags)
        flags_numeric = 1 if 'DF' in flags_str else 0
        
        return pd.DataFrame([[src_port, dst_port, ttl, length, flags_numeric]], 
                          columns=FEATURE_COLUMNS)
    except Exception as e:
        log_error(f"Error extracting features: {e}")
        return None


def detect_packet(packet):
    """Callback function for each sniffed packet."""
    try:
        features_df = extract_features(packet)
        if features_df is not None and model is not None and scaler is not None:
            features_scaled = scaler.transform(features_df)
            prediction = model.predict(features_scaled)[0]
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            label = "Malicious 🚨" if prediction == 0 else "Normal ✅"
            features_list = features_df.values.flatten().tolist()
            
            log_info(f"[{timestamp}] Prediction: {label} | Features: {features_list}")
            print(f"[{timestamp}] Prediction: {label} | Features: {features_list}")
    except Exception as e:
        log_error(f"Error in packet detection: {e}")


def main():
    """Main function to start real-time detection."""
    log_info("Starting MITM Attack Detection System")
    
    # Load models
    if not load_models():
        log_error("Failed to load models. Exiting.")
        sys.exit(1)
    
    # Get network interface
    iface = get_network_interface()
    if not iface:
        log_error("No network interface available. Exiting.")
        sys.exit(1)
    
    log_info(f"Using network interface: {iface}")
    log_info(f"Packet filter: {PACKET_FILTER}")
    log_info("Starting packet capture (Press Ctrl+C to stop)...")
    
    try:
        sniff(filter=PACKET_FILTER, prn=detect_packet, store=False, iface=iface)
    except KeyboardInterrupt:
        log_info("Packet capture stopped by user")
    except PermissionError:
        log_error("Permission denied. Please run with administrator/root privileges.")
        sys.exit(1)
    except Exception as e:
        log_error(f"Error during sniffing: {e}")
        log_error("Make sure you have the correct interface name and necessary permissions.")
        sys.exit(1)


if __name__ == "__main__":
    main()