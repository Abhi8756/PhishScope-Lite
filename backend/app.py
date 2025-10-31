import joblib
import re
import os
import json
import logging
import numpy as np
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from scipy.sparse import hstack
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

# --- Load Environment Variables ---
load_dotenv() 
logging.basicConfig(level=logging.INFO)

# --- Basic Setup ---
app = Flask(__name__)
CORS(app)

# --- Global Variables ---
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
TFIDF_PATH = os.path.join(MODEL_DIR, "tfidf.pkl")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")

# --- Gemini API Config (We still use this for explanations!) ---
API_KEY = os.getenv("GEMINI_API_KEY") 
LLM_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={API_KEY}"
LLM_SYSTEM_PROMPT = """
You are a concise cybersecurity expert. The user will provide an email's sender, subject, and body. 
This email has ALREADY been flagged as 'Phishing' by a machine learning model.
Your job is to provide a 1-2 sentence explanation for *why* it is suspicious. 
Focus on the most obvious phishing signals. 
Do not greet the user. Do not say 'This email is phishing.' Just provide the expert explanation.
If the email seems harmless, explain that the model might be flagging it based on
subtle text patterns or 'false positive'.
"""

if not API_KEY:
    logging.critical("CRITICAL ERROR: GEMINI_API_KEY is not set.")

# --- Load Local ML Models (V5) ---
try:
    logging.info(f"Loading local ML model (V5) from {MODEL_PATH}")
    clf = joblib.load(MODEL_PATH)
    logging.info(f"Loading local TF-IDF (V5) from {TFIDF_PATH}")
    tfidf = joblib.load(TFIDF_PATH)
    logging.info(f"Loading local model metadata (V5) from {META_PATH}")
    with open(META_PATH, 'r') as f:
        meta = json.load(f)
    LEXICAL_FEATURE_NAMES = meta.get('lexical_features', [])
    logging.info(f"Loaded V5 lexical features: {LEXICAL_FEATURE_NAMES}")
    logging.info("\n--- Local ML V5 Artifacts loaded successfully ---")
except Exception as e:
    logging.error(f"CRITICAL ERROR: Could not load V5 models. {e}")
    clf, tfidf, meta, LEXICAL_FEATURE_NAMES = None, None, None, []

# --- V4/V5 Feature Extraction Functions ---
# (These 8 features MUST match the V5 training script)

# 1. TF-IDF Text Cleaner
url_re_simple = re.compile(r"http\S+|https\S+", flags=re.I)
def clean_text_for_tfidf(s):
    s = str(s).lower()
    s = url_re_simple.sub(" ", s); s = re.sub(r"\d+", " ", s)
    s = re.sub(r"[^a-z\s]", " ", s); s = re.sub(r"\s+", " ", s).strip()
    return s

# 2. Lexical Feature Definitions (V4/V5)
re_urgency = re.compile(r'\b(act now|apply now|call now|get it now|do it today|don\'t delete|exclusive deal|get started now|important information|instant|limited time|order now|please read|take action|this won\'t last|urgent|while supplies last|offer expires|time limited)\b', re.I)
re_financial_scam = re.compile(r'\b(100% more|100% free|100% satisfied|additional income|be your own boss|best price|big bucks|billion|cash bonus|cents on the dollar|consolidate debt|double your cash|double your income|earn extra cash|earn money|eliminate bad credit|extra cash|extra income|expect to earn|fast cash|financial freedom|free access|free consultation|free gift|free hosting|free info|free investment|free membership|free money|free preview|free quote|free trial|full refund|get out of debt|get paid|giveaway|increase sales|increase traffic|incredible deal|lower rates|lowest price|make money|million dollars|miracle|money back|once in a lifetime|one time|pennies a day|potential earnings|prize|promise|pure profit|risk-free|satisfaction guaranteed|save big money|save up to|special promotion|serious cash)\b', re.I)
re_unethical = re.compile(r'\b(bulk email|buy direct|cancel at any time|check or money order|congratulations|confidentiality|cures|dear friend|direct email|direct marketing|hidden charges|human growth hormone|internet marketing|lose weight|mass email|meet singles|multi-level marketing|no catch|no cost|no credit check|no fees|no gimmick|no hidden costs|no hidden fees|no interest|no investment|no obligation|no purchase necessary|no questions asked|no strings attached|not junk|notspam|obl|passwords|requires initial investment|social security number|this isn\'t a scam|this isn\'t junk|this isn\'t spam|undisclosed|unsecured credit|unsecured debt|unsolicited|valium|viagra|vicodin|we hate spam|weight loss|xanax|xxx|accept credit cards|as seen on|bargain|beneficiary|billing|bonus|cards accepted|certified|claims|clearance|compare rates|credit card offers|deal|debt|discount|fantastic|in accordance with laws|income|investment|join millions|lifetime|loans|luxury|marketing solution|message contains|mortgage rates|name brand|offer|online marketing|opt in|pre-approved|quote|rates|refinance|removal|reserves the right|score|search engine|sent in compliance|subject to|terms and conditions|trial|unlimited|warranty|web traffic|work from home)\b', re.I)
re_generic_cta = re.compile(r'\b(click below|click here|see for yourself|sign up free|what are you waiting for|will not believe your eyes|winner|winning|you are a winner|you have been selected|buy|order|order status|get|give it away|print form signature|print out and fax|subscribe)\b', re.I)
url_finder = re.compile(r"(?:https?://|www\.|[a-zA-Z0-9-]+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I)

# The new, smarter sender check
def check_sender_suspicious(sender_email):
    sender_email = str(sender_email).lower()
    if not sender_email or "@" not in sender_email:
        return 0 # Not a valid email, but not "suspicious" in our defined way
    
    if re.search(r'\d{3,}', sender_email):
        return 1 # Flags 'user12345@...'
        
    if re.search(r'^(support|security|info|account|service|admin)@', sender_email):
        try:
            v = validate_email(sender_email, check_deliverability=False)
            domain = v.domain
            if domain in ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'mail.com', 'aol.com']:
                return 1 # It's 'support@gmail.com' -> SUSPICIOUS
        except Exception:
            return 1 # Invalid format (e.g., 'support@') is suspicious
            
    return 0 # 'support@mybank.com' is NOT suspicious

# The main feature extractor
def extract_lexical_features(sender, subject, body):
    sender, subject, body = str(sender), str(subject), str(body)
    
    # This list MUST have 8 features, in this exact order:
    features = [
        check_sender_suspicious(sender),          # f_sender_is_susp
        1 if re_urgency.search(subject) else 0,    # f_subject_urgency
        1 if re_urgency.search(body) else 0,       # f_body_urgency
        1 if re_financial_scam.search(body) else 0,# f_body_financial_scam
        1 if re_unethical.search(body) else 0,     # f_body_unethical
        1 if re_generic_cta.search(body) else 0,   # f_body_generic_cta
        len(url_finder.findall(body)),            # f_body_num_urls
        1 if url_finder.search(subject) else 0     # f_subject_has_url
    ]
    return np.array(features, dtype=float).reshape(1, -1) # [1, 8] shape

# 3. LLM Explanation (Unchanged)
def get_llm_explanation(sender, subject, body):
    logging.info("Calling Gemini API for explanation...")
    if not API_KEY: return "Could not generate LLM explanation (API key not configured)."
    
    user_query = f"Sender: {sender}\nSubject: {subject}\nBody: {body}\n\nExpert Explanation:"
    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "systemInstruction": {"parts": [{"text": LLM_SYSTEM_PROMPT}]},
        "generationConfig": { "temperature": 0.5, "maxOutputTokens": 100 }
    }
    
    try:
        response = requests.post(LLM_API_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result:
                return result['candidates'][0]['content']['parts'][0]['text']
            else:
                block_reason = result.get('promptFeedback', {}).get('blockReason', 'Unknown')
                return f"Explanation failed (Prompt blocked by safety filter: {block_reason})."
        else:
            logging.error(f"LLM API Error {response.status_code}: {response.text}")
            return "Could not generate LLM explanation (API error)."
    except Exception as e:
        logging.error(f"Error calling LLM: {e}")
        return "Could not generate LLM explanation."

# --- Prediction Endpoint (V11) ---
@app.route("/predict", methods=["POST"])
def predict_endpoint():
    if clf is None:
        return jsonify({"error": "Model is not loaded. Check server logs."}), 500

    data = request.json
    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")
    
    if sender:
        try:
            validate_email(sender, check_deliverability=False)
        except EmailNotValidError as e:
            logging.warning(f"Invalid sender format: {sender}")
    
    if not subject and not body:
        return jsonify({"error": "No subject or body provided"}), 400

    logging.info(f"V11 Analysis: Sender: {sender}, Subject: {subject[:50]}...")

    try:
        # --- 1. Get ML Model Prediction (V5) ---
        master_text = f"{sender} {subject} {body}"
        cleaned_master_text = clean_text_for_tfidf(master_text)
        X_tfidf = tfidf.transform([cleaned_master_text])
        
        X_lex = extract_lexical_features(sender, subject, body) 
        
        word_count = len(cleaned_master_text.split())
        num_urls = X_lex[0, 6] # f_body_num_urls (it's the 7th item, index 6)
        
        if word_count < 3 and num_urls == 0:
            return jsonify({
                "prediction": "Legitimate", "confidence": 0.0,
                "reasons": ["Input is too short to analyze."]
            })
        
        X_comb = hstack([X_tfidf, X_lex]) 
        
        pred_proba = clf.predict_proba(X_comb)[0]
        result_label = "Phishing" if pred_proba[1] > 0.5 else "Legitimate"
        phishing_confidence = float(pred_proba[1])
        
        logging.info(f"ML Prediction: {result_label}, Confidence: {phishing_confidence:.4f}")

        # --- 2. Get LLM Explanation ---
        reasons = []
        if result_label == "Phishing":
            llm_reason = get_llm_explanation(sender, subject, body)
            reasons.append(llm_reason)
        else:
            reasons.append("Email appears to be legitimate.")

        # 3. Return the full result
        # *** THIS IS THE CORRECTED LINE ***
        return jsonify({
            "prediction": result_label,
            "confidence": phishing_confidence,
            "reasons": reasons
        })

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        logging.exception("Stack trace:")
        return jsonify({"error": "An error occurred during analysis."}), 500

# --- Health Check Endpoint ---
@app.route("/", methods=["GET"])
def health_check():
    status = "OK" if clf is not None else "ERROR: Model not loaded"
    return jsonify({
        "status": status,
        "model_metadata": meta
    })

# --- Run the App ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)