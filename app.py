from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import re
import os
from urllib.parse import urlparse

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from frontend

# Load model and vectorizer
model = joblib.load("fraud_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Stopwords for filtering suspicious keywords
STOPWORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're", "you've", "you'll", "you'd",
    'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his', 'himself', 'she', "she's", 'her', 'hers',
    'herself', 'it', "it's", 'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which',
    'who', 'whom', 'this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been',
    'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an', 'the', 'and', 'but', 'if',
    'or', 'because', 'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against', 'between',
    'into', 'through', 'during', 'before', 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out',
    'on', 'off', 'over', 'under', 'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why',
    'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not',
    'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'will', 'just', 'don', "don't", 'should',
    "should've", 'now', 'd', 'll', 'm', 'o', 're', 've', 'y', 'ain', 'aren', "aren't", 'couldn', "couldn't",
    'didn', "didn't", 'doesn', "doesn't", 'hadn', "hadn't", 'hasn', "hasn't", 'haven', "haven't", 'isn', "isn't",
    'ma', 'mightn', "mightn't", 'mustn', "mustn't", 'needn', "needn't", 'shan', "shan't", 'shouldn', "shouldn't",
    'wasn', "wasn't", 'weren', "weren't", 'won', "won't", 'wouldn', "wouldn't"
}

def extract_urls(text):
    # Matches http://, https://, www. and raw domains with common suspicious TLDs
    tld_pattern = r'(?:com|org|net|xyz|top|pw|info|site|online|club|click|link|security|support|biz|co|cc|tk|ml|ga|cf|gq|loan|work|live|today|email|help)'
    pattern = rf'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.{tld_pattern}(?:/[^\s]*)?)'
    matches = re.findall(pattern, text, re.IGNORECASE)
    
    cleaned = []
    for m in matches:
        m = m.rstrip('.,;!?()[]{}')
        if '.' in m and not re.match(r'^\d+\.\d+$', m):
            cleaned.append(m)
    return list(set(cleaned))

def analyze_url(url):
    parsed_url = url
    if not url.startswith(('http://', 'https://')):
        parsed_url = 'http://' + url
        
    try:
        parsed = urlparse(parsed_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        domain = url.lower()
        path = ""
        
    if ':' in domain:
        domain = domain.split(':')[0]
        
    reasons = []
    risk_score = 0
    threat_signals = set()
    
    # 1. IP Address check
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        risk_score = max(risk_score, 90)
        reasons.append("IP-based URL bypasses standard domain name system")
        threat_signals.add("Suspicious URL")
        
    # 2. Suspicious TLD check
    suspicious_tlds = {'.xyz', '.top', '.pw', '.cc', '.club', '.info', '.support', '.security', '.online', '.site', '.app', '.link', '.click', '.gq', '.cf', '.ml', '.ga', '.tk', '.loan', '.work', '.live', '.today', '.help'}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            risk_score = max(risk_score, 50)
            reasons.append(f"Suspicious top-level domain ({tld}) detected")
            threat_signals.add("Suspicious URL")
            break
            
    # 3. Subdomain nesting
    dots = domain.count('.')
    if dots >= 4:
        risk_score = max(risk_score, 60)
        reasons.append("Excessive subdomain nesting (deep nesting) detected")
        threat_signals.add("Suspicious URL")
        
    # 4. Excessive hyphens
    hyphens = domain.count('-')
    if hyphens >= 3:
        risk_score = max(risk_score, 60)
        reasons.append("Excessive hyphens in domain indicate phishing structure")
        threat_signals.add("Suspicious URL")
        
    # 5. Phishing keywords
    phish_keywords = {'login', 'verify', 'update', 'kyc', 'otp', 'pan', 'account', 'signin', 'verification', 'secure', 'banking', 'payment', 'refund', 'claims', 'bonus'}
    found_kws = [kw for kw in phish_keywords if kw in domain or kw in path]
    if found_kws:
        kw_risk = 30 + (len(found_kws) * 15)
        risk_score = max(risk_score, kw_risk)
        reasons.append(f"Phishing keyword(s) {found_kws} detected in URL")
        threat_signals.add("Suspicious URL")

    # 6. Brand Impersonation
    brands = {
        'amazon': ['amaz0n', 'amzn', 'amazon-security', 'amazon-login'],
        'netflix': ['netfl1x', 'netflix-verify', 'netflix-login'],
        'paypal': ['paypa1', 'paypal-update', 'paypal-verify'],
        'paytm': ['paytm-kyc', 'paytm-update', 'paytm-verify'],
        'google': ['g00gle', 'google-login', 'google-verify'],
        'microsoft': ['micros0ft', 'ms-verify', 'ms-login'],
        'apple': ['app1e', 'apple-verify', 'apple-login'],
        'sbi': ['sbi-yono', 'yonosbi', 'statebankofindia-verify', 'sbi-update', 'sbi-kyc', 'sbi-netbanking'],
        'hdfc': ['hdfc-secure', 'hdfcbank-verify', 'hdfc-update', 'hdfc-kyc', 'hdfc-netbanking'],
        'icici': ['icici-secure', 'icicibank-verify', 'icici-update', 'icici-kyc', 'icici-netbanking'],
        'axis': ['axis-secure', 'axisbank-verify', 'axis-update', 'axis-kyc', 'axis-netbanking']
    }
    
    official_domains = {
        'amazon': 'amazon.com',
        'netflix': 'netflix.com',
        'paypal': 'paypal.com',
        'paytm': 'paytm.com',
        'google': 'google.com',
        'microsoft': 'microsoft.com',
        'apple': 'apple.com',
        'sbi': 'sbi.co.in',
        'hdfc': 'hdfcbank.com',
        'icici': 'icicibank.com',
        'axis': 'axisbank.com'
    }
    
    impersonated_brand = None
    for brand, variants in brands.items():
        off_dom = official_domains[brand]
        is_official = domain == off_dom or domain.endswith('.' + off_dom)
        if not is_official:
            if brand in domain or any(var in domain for var in variants):
                impersonated_brand = brand
                break
                
    if impersonated_brand:
        risk_score = max(risk_score, 95)
        reasons.append(f"Brand impersonation attempt targeting {impersonated_brand.upper()} in URL")
        threat_signals.add("Brand Impersonation")
        threat_signals.add("Suspicious URL")
        
    return {
        'risk_score': min(risk_score, 100),
        'reasons': reasons,
        'threat_signals': list(threat_signals),
        'impersonated_brand': impersonated_brand
    }

def classify_scam_category(message):
    msg_lower = message.lower()
    
    # KYC Scam rules
    kyc_keywords = [
        "kyc", "verification", "update account", "re-kyc", "expired", 
        "documents", "pan card", "aadhaar", "pan", "verify your identity"
    ]
    if any(kw in msg_lower for kw in kyc_keywords):
        return "KYC Verification Scam"
        
    # Banking Scam rules
    banking_keywords = [
        "otp", "bank", "account blocked", "card", "debit", "credit", 
        "transaction", "unauthorized", "withdrawn", "icici", "hdfc", 
        "sbi", "axis", "account suspended", "netbanking", "lock"
    ]
    if any(kw in msg_lower for kw in banking_keywords):
        return "Banking Scam"
        
    # UPI Scam rules
    upi_keywords = [
        "upi", "payment failed", "refund", "gpay", "phonepe", "paytm", 
        "request money", "collect request", "pin", "requesting money", "receive money"
    ]
    if any(kw in msg_lower for kw in upi_keywords):
        return "UPI Scam"
        
    # Lottery Scam rules
    lottery_keywords = [
        "congratulations", "won", "lottery", "cash prize", "draw", 
        "gift card", "reward", "crore", "lakh", "winner", "selected"
    ]
    if any(kw in msg_lower for kw in lottery_keywords):
        return "Lottery Scam"
        
    # Job Scam rules
    job_keywords = [
        "job offer", "salary", "work from home", "part time", 
        "earn money", "daily income", "hiring", "telegram task", 
        "part-time", "jobs", "wfh"
    ]
    if any(kw in msg_lower for kw in job_keywords):
        return "Job Scam"
        
    # Investment Scam rules
    investment_keywords = [
        "investment", "double money", "crypto", "trading", "profit", 
        "returns", "guaranteed income", "bitcoin", "invest"
    ]
    if any(kw in msg_lower for kw in investment_keywords):
        return "Investment Scam"
        
    return "Other Scam"


def extract_reasons(message):
    msg_lower = message.lower()
    reasons = []
    
    # OTP Check
    if "otp" in msg_lower or "pin" in msg_lower:
        reasons.append("OTP/PIN request detected")
        
    # Urgency Check
    urgency_kws = ["immediately", "urgent", "blocked", "suspension", "expires", "action required", "now", "cancel", "unblock"]
    if any(kw in msg_lower for kw in urgency_kws):
        reasons.append("Urgency/threatening language detected")
        
    # Banking Check
    banking_kws = ["bank", "account", "card", "debit", "credit", "transaction", "withdrawn", "icici", "hdfc", "sbi", "axis"]
    if any(kw in msg_lower for kw in banking_kws):
        reasons.append("Banking-related keywords detected")
        
    # UPI Check
    upi_kws = ["upi", "gpay", "phonepe", "paytm", "refund", "failed", "request", "collect"]
    if any(kw in msg_lower for kw in upi_kws):
        reasons.append("UPI payment portal reference")
        
    # Lottery Check
    lottery_kws = ["won", "lottery", "prize", "cash", "crore", "lakh", "gift", "reward", "congratulations"]
    if any(kw in msg_lower for kw in lottery_kws):
        reasons.append("Lottery/Prize reward promises")
        
    # Job Check
    job_kws = ["job", "salary", "work from home", "part time", "earn", "hiring", "income"]
    if any(kw in msg_lower for kw in job_kws):
        reasons.append("Job offer promising income")
        
    # KYC Check
    kyc_kws = ["kyc", "verification", "pan", "aadhaar", "update"]
    if any(kw in msg_lower for kw in kyc_kws):
        reasons.append("KYC/Identity verification request")
        
    # Investment Check
    investment_kws = ["investment", "crypto", "bitcoin", "profit", "returns", "trading"]
    if any(kw in msg_lower for kw in investment_kws):
        reasons.append("Investment/Financial profit promises")
        
    if not reasons:
        reasons.append("Suspicious patterns detected by model")
        
    return reasons

def calculate_rule_boost(message):
    msg_lower = message.lower()
    
    # 1. KYC indicators + Urgency/Suspension
    has_kyc = any(w in msg_lower for w in ["kyc", "re-kyc", "pan card", "aadhaar", "verify your identity", "verification"])
    has_urgency = any(w in msg_lower for w in ["immediately", "urgent", "blocked", "suspension", "expired", "expires", "action required", "lock", "suspended", "before 4", "before 8", "limit"])
    if has_kyc and has_urgency:
        return 70.0  # Fraud
        
    # 2. OTP/PIN requests (very high risk)
    has_otp = "otp" in msg_lower or "one time password" in msg_lower or "verification code" in msg_lower
    if has_otp:
        return 80.0  # Critical/High Fraud
        
    # 3. Lottery/Cash prize + link or contact details
    has_lottery = any(w in msg_lower for w in ["won", "lottery", "cash prize", "crore", "lakh", "cash reward", "draw"])
    has_action = any(w in msg_lower for w in ["claim", "link", "click", "contact", "call", "http", "https", "whatsapp"])
    if has_lottery and has_action:
        return 75.0  # Fraud
    
    # 4. UPI refund / payment failure + link/action
    has_upi = any(w in msg_lower for w in ["upi", "gpay", "phonepe", "paytm", "refund", "failed"])
    if has_upi and has_action:
        return 70.0  # Fraud

    # 5. Job offers work from home promising daily income
    has_job = any(w in msg_lower for w in ["work from home", "telegram task", "daily income", "part time job", "earn money", "salary"])
    if has_job and has_action:
        return 65.0  # Fraud

    # 6. General Banking threat + Urgency (e.g. Account suspended, card blocked)
    has_banking = any(w in msg_lower for w in ["bank", "account blocked", "card", "debit", "credit", "netbanking", "lock"])
    if has_banking and has_urgency:
        return 72.0  # Fraud
        
    return 0.0

def evaluate_threats(message, input_type=None):
    msg_lower = message.strip().lower()
    
    # Auto-detection
    if not input_type:
        if re.match(r'^(https?://|www\.)\S+$', message.strip()) or ('.' in message and ' ' not in message.strip()):
            input_type = 'url'
        else:
            input_type = 'sms'
            
    extracted_urls = extract_urls(message)
    
    # URL Standalone analysis
    if input_type == 'url' or (len(extracted_urls) == 1 and message.strip() == extracted_urls[0]):
        url_res = analyze_url(message.strip())
        risk_score = url_res['risk_score']
        reasons = url_res['reasons']
        threat_signals = set(url_res['threat_signals'])
        
        if not reasons:
            reasons = ["No suspicious URL patterns detected."]
            
        label = "Genuine"
        if risk_score > 55:
            label = "Fraud"
        elif risk_score >= 45:
            label = "Uncertain"
            
        effective_prob = risk_score / 100.0
        if label == "Fraud":
            confidence_score = round(effective_prob * 100, 2)
        elif label == "Genuine":
            confidence_score = round((1 - effective_prob) * 100, 2)
        else:
            confidence_score = round(max(effective_prob, 1 - effective_prob) * 100, 2)
            
        category = "Phishing URL" if label in ["Fraud", "Uncertain"] else "None"
        
        return {
            "prediction": label,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "category": category,
            "threat_signals": list(threat_signals),
            "reasons": reasons,
            "highlighted_message": f'<span class="suspicious-highlight">{message}</span>' if label != "Genuine" else message,
            "input_type": "url",
            "suspicious_words": []
        }
        
    # Text Analysis (SMS, Email, WhatsApp)
    # 1. NLP score
    transformed = vectorizer.transform([message])
    nlp_prob = model.predict_proba(transformed)[0][1]
    nlp_score = round(nlp_prob * 100, 2)
    
    # 2. Rule boost
    rule_boost = calculate_rule_boost(message)
    text_score = max(nlp_score, rule_boost)
    
    # 3. URL scan within text
    url_score = 0
    url_reasons = []
    url_threats = set()
    for url in extracted_urls:
        res = analyze_url(url)
        if res['risk_score'] > url_score:
            url_score = res['risk_score']
        url_reasons.extend(res['reasons'])
        url_threats.update(res['threat_signals'])
        
    # 4. Aggregated risk score
    if extracted_urls:
        risk_score = max(text_score, url_score)
        # Combination boost
        if text_score > 40 and url_score > 40:
            risk_score = min(risk_score + 10.0, 100.0)
    else:
        risk_score = text_score
        
    risk_score = round(risk_score, 2)
    
    # 5. Extract text signals
    text_threats = set()
    
    urgency_kws = ["immediately", "urgent", "blocked", "suspension", "expired", "expires", "action required", "lock", "suspended", "before 4", "before 8", "limit", "now", "cancel", "unblock"]
    if any(kw in msg_lower for kw in urgency_kws):
        text_threats.add("Urgency Language")
        
    otp_kws = ["otp", "pin", "one time password", "verification code", "collect request"]
    if any(kw in msg_lower for kw in otp_kws):
        text_threats.add("OTP Request")
        
    banking_kws = ["bank", "account blocked", "card", "debit", "credit", "netbanking", "lock", "transaction", "withdrawn", "icici", "hdfc", "sbi", "axis"]
    if any(kw in msg_lower for kw in banking_kws):
        text_threats.add("Banking Keywords")
        
    kyc_kws = ["kyc", "re-kyc", "pan card", "aadhaar", "update account", "verification", "verify your identity", "pan"]
    if any(kw in msg_lower for kw in kyc_kws):
        text_threats.add("KYC Verification Request")
        
    # Brand Impersonation check (either in URL or if brand mentioned in suspicious text)
    brands_to_check = ['amazon', 'netflix', 'paypal', 'paytm', 'google', 'microsoft', 'apple', 'sbi', 'hdfc', 'icici', 'axis']
    if risk_score >= 45:
        for brand in brands_to_check:
            if brand in msg_lower:
                text_threats.add("Brand Impersonation")
                break
                
    all_signals = text_threats.union(url_threats)
    
    label = "Genuine"
    if risk_score > 55:
        label = "Fraud"
    elif risk_score >= 45:
        label = "Uncertain"
        
    effective_prob = risk_score / 100.0
    if label == "Fraud":
        confidence_score = round(effective_prob * 100, 2)
    elif label == "Genuine":
        confidence_score = round((1 - effective_prob) * 100, 2)
    else:
        confidence_score = round(max(effective_prob, 1 - effective_prob) * 100, 2)
        
    category = "None"
    if label in ["Fraud", "Uncertain"]:
        category = classify_scam_category(message)
        # If categorized as Other but URL was highly suspicious, adjust to Phishing URL
        if category == "Other Scam" and url_score > 55 and not any(kw in msg_lower for kw in ["kyc", "otp", "pin", "upi", "won", "lottery", "job", "salary", "investment"]):
            category = "Phishing URL"
            
    # Explainable AI: highlighted text & words
    analyzer = vectorizer.build_analyzer()
    tokens = analyzer(message)
    vocab = vectorizer.vocabulary_
    coef = model.coef_[0]
    
    suspicious_words = []
    for token in set(tokens):
        if token in vocab:
            idx = vocab[token]
            weight = coef[idx]
            if weight > 0:
                suspicious_words.append((token, weight))
    suspicious_words.sort(key=lambda x: x[1], reverse=True)
    top_suspicious = [w[0] for w in suspicious_words if w[0].lower() not in STOPWORDS]
    top_suspicious_display = top_suspicious[:8]
    
    words_to_highlight = [w[0] for w in suspicious_words]
    if label in ["Fraud", "Uncertain"]:
        rule_kws = ["kyc", "re-kyc", "pan card", "aadhaar", "otp", "pin", "verification", "expired", "suspension", "blocked", "immediately", "urgent", "draw", "lottery", "cash prize", "won", "reward", "upi", "netbanking", "lock", "limit"]
        for kw in rule_kws:
            if kw in msg_lower:
                for token in set(tokens):
                    if kw in token.lower() and token not in words_to_highlight:
                        words_to_highlight.append(token)
                        
    highlighted_message = message
    if words_to_highlight:
        sorted_highlight_words = sorted(set(words_to_highlight), key=len, reverse=True)
        pattern = re.compile(rf'\b({"|".join(re.escape(w) for w in sorted_highlight_words)})\b', re.IGNORECASE)
        highlighted_message = pattern.sub(lambda m: f'<span class="suspicious-highlight">{m.group(0)}</span>', message)
        
    for url in extracted_urls:
        res = analyze_url(url)
        if res['risk_score'] > 45:
            if url in highlighted_message and f'<span class="suspicious-highlight">{url}</span>' not in highlighted_message:
                highlighted_message = highlighted_message.replace(url, f'<span class="suspicious-highlight">{url}</span>')
                
    reasons = []
    if label in ["Fraud", "Uncertain"]:
        reasons = extract_reasons(message)
        for ur in url_reasons:
            if ur not in reasons:
                reasons.append(ur)
    else:
        reasons = ["No significant threat patterns detected in message."]
        
    return {
        "prediction": label,
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "category": category,
        "threat_signals": list(all_signals),
        "reasons": reasons,
        "highlighted_message": highlighted_message,
        "input_type": input_type,
        "suspicious_words": top_suspicious_display
    }

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "alive"})

@app.route("/", methods=["GET"])
def home():
    return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend"), "index.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend"), "dashboard.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        message = data.get("message", "")
        input_type = data.get("input_type", "")
        
        if not message.strip():
            return jsonify({"error": "Message is empty"}), 400
            
        result = evaluate_threats(message, input_type)
        
        risk_score = result["risk_score"]
        severity = "Low Risk"
        if risk_score > 85:
            severity = "Critical Risk"
        elif risk_score > 60:
            severity = "High Risk"
        elif risk_score > 30:
            severity = "Medium Risk"
            
        return jsonify({
            "prediction": result["prediction"],
            "probability": risk_score,
            "risk_score": risk_score,
            "confidence_score": result["confidence_score"],
            "severity": severity,
            "category": result["category"],
            "suspicious_words": result["suspicious_words"],
            "reasons": result["reasons"],
            "highlighted_message": result["highlighted_message"],
            "input_type": result["input_type"],
            "threat_signals": result["threat_signals"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
