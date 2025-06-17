import os
import requests
from flask import Flask, render_template, request
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Step 1: Download model.pkl if not present
MODEL_URL = "https://drive.google.com/uc?export=download&id=106worGrLQ2KSrb07JZPLEPiIKnhJ1MCW"
MODEL_PATH = "model.pkl"

if not os.path.exists(MODEL_PATH):
    print("Downloading model.pkl from Google Drive...")
    with requests.get(MODEL_URL, stream=True) as r:
        with open(MODEL_PATH, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    print("Download complete.")

app = Flask(__name__)
model = joblib.load(MODEL_PATH)

# Encoders (must match training)
protocol_encoder = LabelEncoder().fit(['tcp', 'udp', 'icmp'])
service_encoder = LabelEncoder().fit(['http', 'ftp', 'smtp', 'domain_u', 'other'])
flag_encoder = LabelEncoder().fit(['SF', 'S0', 'REJ', 'RSTO'])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    features = [
        int(request.form['duration']),
        protocol_encoder.transform([request.form['protocol_type']])[0],
        service_encoder.transform([request.form['service']])[0],
        flag_encoder.transform([request.form['flag']])[0],
        int(request.form['src_bytes']),
        int(request.form['dst_bytes']),
        int(request.form['count']),
        int(request.form['srv_count'])
    ]
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    result_type = "Normal" if prediction.lower() == "normal" else "Attack"
    return render_template('result.html', result_type=result_type, attack_type=prediction.upper())

@app.route('/assist')
def assist():
    return render_template('assist.html')

if __name__ == "__main__":
    app.run(debug=True)
