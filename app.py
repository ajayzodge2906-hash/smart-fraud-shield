from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

# Initialize Flask app
app = Flask(__name__)

# ✅ FIX 1: Proper CORS for Render
CORS(app, resources={r"/*": {"origins": "*"}})

# Load model and vectorizer
model = joblib.load("fraud_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ✅ FIX 2: Health check (VERY IMPORTANT for Render)
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "alive"})

@app.route("/", methods=["GET"])
def home():
    return "✅ Smart Fraud Shield API is running!"

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        message = data.get("message", "")

        if not message.strip():
            return jsonify({"error": "Message is empty"}), 400

        transformed = vectorizer.transform([message])
        prediction = model.predict(transformed)[0]
        probability = model.predict_proba(transformed)[0][1]

        label = "Fraud" if prediction == 1 else "Genuine"

        return jsonify({
            "prediction": label,
            "probability": round(probability * 100, 2)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ❌ DO NOT use app.run() on Render
# Render uses gunicorn automatically
