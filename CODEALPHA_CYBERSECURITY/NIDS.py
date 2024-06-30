import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# Load the dataset
url = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]
data = pd.read_csv(url, names=columns)

# Encode categorical features
categorical_features = ['protocol_type', 'service', 'flag']
encoder = LabelEncoder()
for feature in categorical_features:
    data[feature] = encoder.fit_transform(data[feature])

# Split features and labels
X = data.drop('label', axis=1)
y = data['label']

# Binary classification: normal vs attack
y = y.apply(lambda x: 0 if x == 'normal.' else 1)

# Normalize the feature set
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Train a Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate the model
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
from scapy.all import sniff
import numpy as np

# Function to process packets
def process_packet(packet):
    # Extract features from packet (placeholder for real feature extraction)
    # This should match the features used during training
    features = [0] * len(columns)  # Replace with actual feature extraction
    features = np.array(features).reshape(1, -1)
    
    # Normalize the features
    features_scaled = scaler.transform(features)
    
    # Predict using the trained model
    prediction = model.predict(features_scaled)[0]
    
    # Check if the prediction indicates an attack
    if prediction == 1:
        print("Intrusion detected!")
    else:
        print("Normal traffic.")
    return prediction

# Sniff packets (requires root privileges)
# Replace 'iface' with your network interface
sniff(iface='eth0', prn=process_packet)
