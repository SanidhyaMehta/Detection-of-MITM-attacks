## File: utils/config.py
# Configuration settings for the project
import os
from pathlib import Path

# Base directory (project root)
BASE_DIR = Path(__file__).parent.parent

# Dataset paths
DATASET_PATH = BASE_DIR / "datasets" / "raw_packets.csv"
PREPROCESSED_DATA_PATH = BASE_DIR / "datasets" / "preprocessed_data.csv"
LABELED_DATA_PATH = BASE_DIR / "labeled_packet_data.csv"
CLEANED_DATA_PATH = BASE_DIR / "cleaned_packets.csv"
CAPTURED_PACKETS_PATH = BASE_DIR / "captured_packets.csv"
ENHANCED_PACKETS_PATH = BASE_DIR / "enhanced_packets.csv"

# Model paths
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "mitm_detector.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
LEGACY_MODEL_PATH = BASE_DIR / "logistic_model.pkl"
LEGACY_SCALER_PATH = BASE_DIR / "scaler.pkl"

# Logs directory
LOGS_DIR = BASE_DIR / "logs"
LOGS_FILE = LOGS_DIR / "logs.log"

# Network interface configuration
# Can be overridden via environment variable: NETWORK_INTERFACE
# Windows format: r"\Device\NPF_{GUID}"
# Linux/Mac format: "eth0", "wlan0", "en0", etc.
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", None)

# Packet capture settings
PACKET_LIMIT = int(os.getenv("PACKET_LIMIT", "50"))  # Number of packets to capture
PACKET_FILTER = os.getenv("PACKET_FILTER", "ip")  # BPF filter for packet capture

# Feature columns for ML model
FEATURE_COLUMNS = ['Source Port', 'Destination Port', 'TTL', 'Length', 'Flags']
TARGET_COLUMN = 'Label'

# Model training parameters
TEST_SIZE = float(os.getenv("TEST_SIZE", "0.2"))
RANDOM_STATE = int(os.getenv("RANDOM_STATE", "42"))

# Create necessary directories
MODEL_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
(BASE_DIR / "datasets").mkdir(exist_ok=True)