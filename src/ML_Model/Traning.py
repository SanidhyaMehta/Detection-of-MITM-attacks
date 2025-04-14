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

# Evaluation

# print("Accuracy:", accuracy_score(y_test, y_pred_log))
# print("\nClassification Report:\n", classification_report(y_test, y_pred_log))
# print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_log))

import joblib

# Save the trained logistic regression model
joblib.dump(log_reg, "logistic_model.pkl")

# Save the StandardScaler used for feature scaling
joblib.dump(scaler, "scaler.pkl")




