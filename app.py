from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from frontend

# Load model and vectorizer
model = joblib.load("fraud_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

@app.route("/", methods=["GET"])
def home():
    return "✅ Smart Fraud Shield API is running!"

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Get JSON data
        data = request.get_json()
        message = data.get("message", "")

        if not message.strip():
            return jsonify({"error": "Message is empty"}), 400

        # Transform input
        transformed = vectorizer.transform([message])

        # Make prediction
        prediction = model.predict(transformed)[0]
        probability = model.predict_proba(transformed)[0][1]  # Probability of fraud (class 1)

        label = "Fraud" if prediction == 1 else "Genuine"

        # Return result
        return jsonify({
            "prediction": label,
            "probability": round(probability * 100, 2)  # Convert to percentage
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Run app locally
if __name__ == "__main__":
    app.run(debug=True)
