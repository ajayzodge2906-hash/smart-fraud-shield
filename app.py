
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle

app = Flask(__name__)
CORS(app)  # Enable CORS

# Load model and vectorizer
with open("model.pkl", "rb") as f:
    model, vectorizer = pickle.load(f)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Smart Fraud Shield API is running 🚀"})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "No message provided"}), 400

    message = data["message"]
    vectorized_msg = vectorizer.transform([message])
    prediction = model.predict(vectorized_msg)[0]
    probability = model.predict_proba(vectorized_msg)[0][1]

    return jsonify({
        "prediction": "Fraud" if prediction == 1 else "Genuine",
        "fraud_probability": round(probability * 100, 2)
    })

if __name__ == "__main__":
    app.run(debug=True)
