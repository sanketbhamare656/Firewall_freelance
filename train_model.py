import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load training data
data = pd.read_csv("packets.csv")

# Features and target
X = data[['src_ip', 'dst_ip', 'port', 'protocol', 'packet_size']]
y = data['label']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save model
joblib.dump(model, "firewall_model.pkl")

print("✅ Model trained and saved successfully!")
print(f"📊 Training samples: {len(X)}")
print(f"🎯 Features: {list(X.columns)}")