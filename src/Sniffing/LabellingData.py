import pandas as pd
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))
from utils.config import CLEANED_DATA_PATH, LABELED_DATA_PATH, FEATURE_COLUMNS
from utils.logger import log_info, log_error


def label_packet(row):
    """
    Labeling logic for MITM attack detection.
    Returns 0 for Normal, 1 for Suspicious/Attack.
    """
    # Suspicious patterns:
    # - High destination port (> 50000) - often used in attacks
    # - Low TTL (< 30) - may indicate spoofing
    # - Large packet length (> 1000) - potential data exfiltration
    # - Flags == 0 - unusual flag combination
    if (row['Destination Port'] > 50000 or
        row['TTL'] < 30 or
        row['Length'] > 1000 or
        row['Flags'] == 0):
        return 1  # Suspicious / Attack
    return 0  # Normal


def label_data():
    """Label packet data for training."""
    try:
        # Check if cleaned data exists
        if not CLEANED_DATA_PATH.exists():
            log_error(f"Cleaned data file not found: {CLEANED_DATA_PATH}")
            log_error("Please clean your packet data first")
            return False
        
        log_info(f"Loading cleaned data from: {CLEANED_DATA_PATH}")
        df = pd.read_csv(CLEANED_DATA_PATH)
        
        log_info(f"Dataset shape: {df.shape}")
        log_info(f"Columns: {df.columns.tolist()}")
        
        # Validate required columns (at least Destination Port, TTL, Length, Flags)
        required_cols = ['Destination Port', 'TTL', 'Length', 'Flags']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            log_error(f"Missing required columns: {missing_cols}")
            log_error(f"Available columns: {df.columns.tolist()}")
            return False
        
        # Check if Source Port is missing (may need to add default)
        if 'Source Port' not in df.columns:
            log_info("Source Port column not found, adding default value 0")
            df['Source Port'] = 0
        
        # Clean and convert Flags column
        log_info("Processing Flags column...")
        df['Flags'] = df['Flags'].fillna(0)
        try:
            df['Flags'] = pd.to_numeric(df['Flags'], errors='coerce').fillna(0).astype(int)
        except Exception as e:
            log_error(f"Error converting Flags to numeric: {e}")
            df['Flags'] = 0
        
        # Apply labeling logic
        log_info("Applying labeling logic...")
        df['Label'] = df.apply(label_packet, axis=1)
        
        # Show label distribution
        label_counts = df['Label'].value_counts()
        log_info("=" * 50)
        log_info("Label Distribution:")
        log_info(f"Normal (0): {label_counts.get(0, 0)} packets")
        log_info(f"Suspicious/Attack (1): {label_counts.get(1, 0)} packets")
        log_info("=" * 50)
        
        # Ensure all required feature columns exist
        missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]
        if missing_features:
            log_error(f"Missing feature columns: {missing_features}")
            return False
        
        # Save labeled data
        log_info(f"Saving labeled data to: {LABELED_DATA_PATH}")
        df.to_csv(LABELED_DATA_PATH, index=False)
        
        log_info(f"Successfully labeled {len(df)} packets!")
        return True
        
    except Exception as e:
        log_error(f"Error during data labeling: {e}")
        import traceback
        log_error(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = label_data()
    sys.exit(0 if success else 1)


