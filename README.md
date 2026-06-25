# Smart Fraud Shield

Smart Fraud Shield is an advanced multi-channel fraud detection platform. It uses a **Unified Fraud Intelligence Engine** to analyze messages across **SMS, Email, URL, and WhatsApp** channels, extracting structured threat signals, calculating risk scores, classifying scam categories, and presenting explainable AI (XAI) insights and real-time dashboard analytics.

---

## 🚀 Key Features

### 1. Unified Fraud Intelligence Engine
*   **Multi-Input Preprocessing**: Extracts text and automatically parses URLs using regular expressions.
*   **NLP Fraud Model**: standard TF-IDF + Logistic Regression on text content.
*   **Rule-Based Threat Engine**: Flags common scam characteristics (KYC expiry, OTP requests, urgent account blocks).
*   **URL Analyzer**: Evaluates domains for IP-based hosting, suspicious TLDs (e.g., `.xyz`, `.online`, `.top`), excessive subdomains, brand impersonation (typosquatting), and phishing path terms.
*   **Compound Risk Scoring**: Aggregates risk from both text and URL checks. Mixed-content attacks receive a $+10\%$ combination boost to represent the compounded threat.

### 2. Structured Threat Signal System
Extracts and displays 6 key threat signals:
*   `Suspicious URL`
*   `Urgency Language`
*   `OTP Request`
*   `Banking Keywords`
*   `Brand Impersonation`
*   `KYC Verification Request`

Detected signals are shown in a clean checklist on the UI result panel, and saved to the database.

### 3. Segmented Pill Tab Channel Selector
*   Includes styled segmented buttons for **SMS, Email, URL, and WhatsApp**.
*   Dynamically changes input area placeholder text and validations.
*   Applies channel-specific active border glows on focus:
    *   **SMS**: Teal/Emerald glow
    *   **Email**: Blue glow
    *   **URL**: Indigo/Violet glow
    *   **WhatsApp**: Green glow

### 4. Scam Categories
*   **Banking Scam**
*   **UPI Scam**
*   **Job Scam**
*   **Lottery Scam**
*   **Investment Scam**
*   **KYC Verification Scam**
*   **Phishing URL**
*   **Other Scam**

### 5. Explainable AI (XAI)
*   **Keyword Highlighting**: Visualizes exactly which words or domain segments drove the threat prediction in red-dashed highlighted text.
*   **Top Suspicious Words**: Displays the top scikit-learn model-weighted vocabulary tokens found in the message (excluding stopwords).
*   **Analysis Breakdown**: Lists human-readable reasons explaining the threat category and indicators.

### 6. Interactive Analytics Dashboard
Served on `/dashboard`, visualizes real-time metrics fetched from Firestore using Chart.js:
*   **New KPIs**: **Most Attacked Channel** and **Most Common Threat Signal** are calculated dynamically.
*   **Stacked Charts Layout**:
    *   **Pie Chart**: Fraud vs. Genuine vs. Uncertain distribution.
    *   **Doughnut Chart**: Input Channel Distribution (SMS vs. Email vs. URL vs. WhatsApp).
    *   **Bar Chart**: Scam Category Distribution (includes the new `Phishing URL` category).
*   **Recent Scans Log**: Displays the last 10 messages checked along with their channel icons (💬, 📧, 🔗, 🟢) and timestamps.

---

## 📂 Project Directory Structure

```text
smart-fraud-shield/
├── app.py                     # Flask API backend (Unified Engine, URL Analyzer)
├── requirements.txt           # Python dependency file
├── Procfile                   # Deployment configuration (Render/Heroku)
├── fraud_model.pkl            # Trained Logistic Regression classifier
├── vectorizer.pkl             # Trained TF-IDF Vectorizer
└── frontend/                  # Static frontend files
    ├── index.html             # Main scanner page (Pill selector, Threat Signals)
    ├── dashboard.html         # Analytics dashboard page (Three charts, Channel KPIs)
    └── firebase.js            # Firebase SDK configuration
```

---

## 📂 Firestore Database Schema

Firestore logs are extended with `input_type` and `threat_signals` while maintaining backward compatibility with older logs:
```json
{
  "message": "Verify your KYC details immediately: https://sbi-secure-kyc-verify.online",
  "score": 100.0,
  "prediction": "Fraud",
  "category": "KYC Verification Scam",
  "severity": "Critical Risk",
  "confidence_score": 100.0,
  "input_type": "sms",
  "threat_signals": [
    "Suspicious URL",
    "Urgency Language",
    "KYC Verification Request",
    "Brand Impersonation"
  ],
  "reported": false,
  "reportedAt": "Timestamp"
}
```

---

## 🛠️ Local Setup & Running Instructions

1.  **Install Python Dependencies**:
    Make sure you have Python 3.8+ installed. Run:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Flask Server**:
    Start the local development server:
    ```bash
    python app.py
    ```
    The backend API runs on `http://127.0.0.1:5000/`.

3.  **Open the Web Application**:
    *   **Main Scanner Interface**: Open `frontend/index.html` directly in a browser (or via a live server extension). The frontend automatically routes local checks to your local Flask backend, and calls Render when deployed to production.
    *   **Analytics Dashboard**: Open `http://127.0.0.1:5000/dashboard` in the browser while the Flask server is running.
