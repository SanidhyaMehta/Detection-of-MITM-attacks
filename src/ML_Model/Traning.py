import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load the labeled data
df = pd.read_csv("labeled_packet_data.csv")  

features = ['Source Port', 'Destination Port', 'TTL', 'Length', 'Flags']
target = 'Label'

X = df[features]
y = df[target]

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

#  spliting into train/test sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Training the Logistic Regression model
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)

# Predict on test set
y_pred_log = log_reg.predict(X_test)

import os
import joblib


# Get the base directory (parent of /src)
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Save the trained logistic regression model in the base directory
joblib.dump(log_reg, os.path.join(base_dir, "logistic_model.pkl"))

# Save the StandardScaler used for feature scaling in the base directory
joblib.dump(scaler, os.path.join(base_dir, "scaler.pkl"))
