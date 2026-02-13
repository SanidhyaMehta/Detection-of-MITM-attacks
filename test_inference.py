import pandas as pd
import joblib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))
from utils.config import MODEL_PATH, SCALER_PATH, LABELED_DATA_PATH, FEATURE_COLUMNS
from utils.logger import log_info, log_error


def test_inference():
    """Test model inference with sample data."""
    try:
        # Check if model files exist
        if not MODEL_PATH.exists():
            log_error(f"Model file not found: {MODEL_PATH}")
            log_error("Please train and convert the model first")
            return False
        
        if not SCALER_PATH.exists():
            log_error(f"Scaler file not found: {SCALER_PATH}")
            log_error("Please train and convert the model first")
            return False
        
        if not LABELED_DATA_PATH.exists():
            log_error(f"Test data file not found: {LABELED_DATA_PATH}")
            log_error("Please ensure labeled_packet_data.csv exists")
            return False
        
        # Load model and scaler
        log_info(f"Loading model from: {MODEL_PATH}")
        model = joblib.load(MODEL_PATH)
        
        log_info(f"Loading scaler from: {SCALER_PATH}")
        scaler = joblib.load(SCALER_PATH)
        
        # Load test data
        log_info(f"Loading test data from: {LABELED_DATA_PATH}")
        df = pd.read_csv(LABELED_DATA_PATH)
        
        # Validate required columns
        missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
        if missing_cols:
            log_error(f"Required feature columns missing: {missing_cols}")
            log_error(f"Available columns: {df.columns.tolist()}")
            return False
        
        # Prepare sample
        sample = df[FEATURE_COLUMNS].iloc[0:1]
        sample_scaled = scaler.transform(sample)
        pred = model.predict(sample_scaled)
        
        # Display results
        log_info("=" * 50)
        log_info("Model Inference Test Results")
        log_info("=" * 50)
        log_info(f"Sample features: {sample.values.tolist()}")
        log_info(f"Prediction: {pred.tolist()}")
        log_info(f"Label meaning: {'Malicious 🚨' if pred[0] == 0 else 'Normal ✅'}")
        log_info("=" * 50)
        
        return True
        
    except Exception as e:
        log_error(f"Error during inference test: {e}")
        import traceback
        log_error(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = test_inference()
    sys.exit(0 if success else 1)
