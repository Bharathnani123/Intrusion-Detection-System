import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("kddcup.data.corrected", header=None)

# Define column names (41 features + label)
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label'
]

df.columns = columns

# Select top 8 features
features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
X = df[features].copy()

# Encode categorical columns
for col in ['protocol_type', 'service', 'flag']:
    X[col] = LabelEncoder().fit_transform(X[col])

# Keep full label (with attack types)
df['label'] = df['label'].str.strip('.')
y = df['label']

# Train model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = DecisionTreeClassifier()
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "model.pkl")

# Evaluate accuracy
accuracy = model.score(X_test, y_test)
print(f"Model trained and saved as model.pkl")
print(f"Accuracy on test data: {accuracy * 100:.2f}%")
