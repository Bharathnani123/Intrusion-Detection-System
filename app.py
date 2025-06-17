from flask import Flask, render_template, request
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
model = joblib.load("model.pkl")

# Encoders (must match what was used during training)
protocol_encoder = LabelEncoder().fit(['tcp', 'udp', 'icmp'])
service_encoder = LabelEncoder().fit(['http', 'ftp', 'smtp', 'domain_u', 'other'])
flag_encoder = LabelEncoder().fit(['SF', 'S0', 'REJ', 'RSTO'])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Collect input features from form
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

    # Make prediction
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]

    # Determine result type and label
    result_type = "Normal" if prediction.lower() == "normal" else "Attack"
    attack_type = prediction.upper()

    return render_template('result.html', result_type=result_type, attack_type=attack_type)
@app.route('/assist')
def assist():
    return render_template('assist.html')

if __name__ == "__main__":
    app.run(debug=True)
