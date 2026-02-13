## File: tests/test_ml.py
import os
import joblib

## imported some more libraries

def test_model_exists():
    """Check if trained ML model exists."""
    assert os.path.isfile("models/mitm_detector.pkl"), "Trained model is missing"
    print("ML model test passed.")

test_model_exists()