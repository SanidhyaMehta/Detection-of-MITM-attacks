import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))
from utils.config import (
    LABELED_DATA_PATH, FEATURE_COLUMNS, TARGET_COLUMN,
    TEST_SIZE, RANDOM_STATE, LEGACY_MODEL_PATH, LEGACY_SCALER_PATH, MODEL_DIR
)
from utils.logger import log_info, log_error


def train_model():
    """Train the MITM detection model."""
    try:
        # Check if labeled data exists
        if not LABELED_DATA_PATH.exists():
            log_error(f"Labeled data file not found: {LABELED_DATA_PATH}")
            return False
        
        log_info(f"Loading labeled data from: {LABELED_DATA_PATH}")
        df = pd.read_csv(LABELED_DATA_PATH)
        
        # Validate required columns
        missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
        if missing_cols:
            log_error(f"Required feature columns missing: {missing_cols}")
            log_error(f"Available columns: {df.columns.tolist()}")
            return False
        
        if TARGET_COLUMN not in df.columns:
            log_error(f"Target column '{TARGET_COLUMN}' not found in data")
            log_error(f"Available columns: {df.columns.tolist()}")
            return False
        
        # Prepare features and target
        X = df[FEATURE_COLUMNS]
        y = df[TARGET_COLUMN]
        
        log_info(f"Dataset shape: {df.shape}")
        log_info(f"Features: {FEATURE_COLUMNS}")
        log_info(f"Target distribution:\n{y.value_counts()}")
        
        # Scale the features
        log_info("Scaling features...")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split into train/test sets
        log_info(f"Splitting data: {int((1-TEST_SIZE)*100)}% train, {int(TEST_SIZE*100)}% test")
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
        )
        
        log_info(f"Training set: {X_train.shape[0]} samples")
        log_info(f"Test set: {X_test.shape[0]} samples")
        
        # Train the Logistic Regression model
        log_info("Training Logistic Regression model...")
        log_reg = LogisticRegression(random_state=RANDOM_STATE, max_iter=1000)
        log_reg.fit(X_train, y_train)
        log_info("Model training completed!")
        
        # Predict on test set
        log_info("Evaluating model on test set...")
        y_pred_log = log_reg.predict(X_test)
        
        # Evaluation metrics
        accuracy = accuracy_score(y_test, y_pred_log)
        log_info("=" * 50)
        log_info("Model Evaluation Results")
        log_info("=" * 50)
        log_info(f"Accuracy: {accuracy:.4f}")
        log_info("\nClassification Report:")
        log_info(classification_report(y_test, y_pred_log))
        log_info("\nConfusion Matrix:")
        log_info(str(confusion_matrix(y_test, y_pred_log)))
        log_info("=" * 50)
        
        # Save the trained model and scaler
        MODEL_DIR.mkdir(exist_ok=True)
        
        log_info(f"Saving model to: {LEGACY_MODEL_PATH}")
        joblib.dump(log_reg, LEGACY_MODEL_PATH)
        
        log_info(f"Saving scaler to: {LEGACY_SCALER_PATH}")
        joblib.dump(scaler, LEGACY_SCALER_PATH)
        
        log_info("Model and scaler saved successfully!")
        log_info("Note: Run 'python convert_models.py' to convert to production format")
        
        return True
        
    except Exception as e:
        log_error(f"Error during model training: {e}")
        import traceback
        log_error(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = train_model()
    sys.exit(0 if success else 1)




