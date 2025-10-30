import joblib
import re
import os
import json
import logging
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from scipy.sparse import hstack

# --- Basic Setup ---
app = Flask(__name__)
CORS(app) # Allow requests from our frontend
logging.basicConfig(level=logging.INFO)

# --- Global Variables ---
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
TFIDF_PATH = os.path.join(MODEL_DIR, "tfidf.pkl")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")

# --- Load Models and Artifacts ---
try:
    logging.info(f"Loading model from {MODEL_PATH}")
    clf = joblib.load(MODEL_PATH)
    
    logging.info(f"Loading tfidf from {TFIDF_PATH}")
    tfidf = joblib.load(TFIDF_PATH)
    
    logging.info(f"Loading model metadata from {META_PATH}")
    with open(META_PATH, 'r') as f:
        meta = json.load(f)
    
    # This is the key for V2 Explainability!
    LEXICAL_FEATURE_NAMES = meta.get('lexical_features', [])
    if not LEXICAL_FEATURE_NAMES:
        logging.warning("WARNING: 'lexical_features' not found in meta.json. Explainability will be limited.")
    
    logging.info(f"Loaded model metadata. Lexical features: {LEXICAL_FEATURE_NAMES}")
    logging.info("\n--- Artifacts loaded successfully (V2 Model) ---")

except FileNotFoundError as e:
    logging.error(f"CRITICAL ERROR: Model file not found. {e}")
    logging.error("Please make sure 'model.pkl', 'tfidf.pkl', and 'model_meta.json' are in the 'models' directory.")
    clf = None
    tfidf = None
    meta = None
    LEXICAL_FEATURE_NAMES = []
except Exception as e:
    logging.error(f"An unexpected error occurred during model loading: {e}")
    clf = None
    tfidf = None
    meta = None
    LEXICAL_FEATURE_NAMES = []


# --- V2 Feature Extraction Functions ---
# These MUST match the new training script

# 1. TF-IDF Text Cleaner
url_re_simple = re.compile(r"http\S+|https\S+", flags=re.I)
def clean_text_for_tfidf(s):
    s = str(s).lower()
    s = url_re_simple.sub(" ", s) 
    s = re.sub(r"\d+", " ", s)
    s = re.sub(r"[^a-z\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

# 2. Lexical Feature Definitions
# These regexes must be identical to the ones in the training script
subject_susp_words = re.compile(r'urgent|action required|verify|account|security|alert|update|password|important|invoice|payment|due|suspicious', re.I)
subject_caps_words = re.compile(r'\b[A-Z]{4,}\b')
body_susp_words = re.compile(r'click here|verify your account|update your password|bank|credit card|ssn|social security|login|username|confidential|winner|congratulations|prize', re.I)
url_finder = re.compile(r"(?:https?://|www\.|[a-zA-Z0-9-]+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I)
sender_susp_re = re.compile(r'(\d+.*@|.*@(?:gmail|hotmail|yahoo|outlook|mail|service|support|info|account|security)\.)', re.I)

def extract_lexical_features(sender, subject, body):
    """ Extracts the 5 lexical features from raw text inputs. """
    sender, subject, body = str(sender), str(subject), str(body)
    
    features = [
        1 if subject_susp_words.search(subject) else 0,  # f_subject_susp_words
        1 if subject_caps_words.search(subject) else 0,  # f_subject_has_caps
        1 if body_susp_words.search(body) else 0,        # f_body_susp_words
        len(url_finder.findall(body)),                   # f_body_num_urls
        1 if sender_susp_re.search(sender) else 0        # f_sender_is_susp
    ]
    return np.array(features, dtype=float).reshape(1, -1) # [1, 5] shape

# 3. Explainability "Reason" Generator
# This maps our feature names to human-readable reasons
REASON_MAP = {
    "f_subject_susp_words": "Subject line contains suspicious keywords (e.g., 'urgent', 'verify', 'password').",
    "f_subject_has_caps": "Subject line uses excessive capitalization.",
    "f_body_susp_words": "Email body contains suspicious phrases (e.g., 'click here', 'bank', 'login').",
    "f_body_num_urls": "Email body contains one or more links.", # We can just say it has links
    "f_sender_is_susp": "Sender's email address appears suspicious (e.g., from a generic provider or contains numbers)."
}

def get_prediction_reasons(lexical_features_array, prediction_label):
    """ Generates a list of reasons for the prediction. """
    reasons = []
    # We only show reasons if it's Phishing
    if prediction_label == "Phishing":
        for i, feature_name in enumerate(LEXICAL_FEATURE_NAMES):
            # Check if the feature was "on" (value > 0)
            if lexical_features_array[0, i] > 0:
                if feature_name in REASON_MAP:
                    reasons.append(REASON_MAP[feature_name])
    
    if prediction_label == "Legitimate" and not reasons:
        reasons.append("Email passes all heuristic checks. No common phishing indicators found.")
        
    return reasons


# --- Prediction Endpoint (V4) ---
@app.route("/predict", methods=["POST"])
def predict_endpoint():
    if clf is None:
        return jsonify({"error": "Model is not loaded. Check server logs."}), 500

    data = request.json
    
    # We now expect 3 fields from the frontend
    sender = data.get("sender", "unknown@unknown.com")
    subject = data.get("subject", "")
    body = data.get("body", "")
    
    if not subject and not body:
        return jsonify({"error": "No subject or body provided"}), 400

    logging.info(f"V2 Analysis: Sender: {sender}, Subject: {subject[:50]}...")

    try:
        # 1. Create 'master_text' for TF-IDF
        master_text = f"{sender} {subject} {body}"
        
        # 2. Clean and transform for TF-IDF
        cleaned_master_text = clean_text_for_tfidf(master_text)
        X_tfidf = tfidf.transform([cleaned_master_text])
        
        # 3. Extract Lexical Features
        X_lex = extract_lexical_features(sender, subject, body)
        
        # 4. Check for "too short" inputs (our old V3 bug fix)
        word_count = len(cleaned_master_text.split())
        num_urls = X_lex[0, 3] # Get f_body_num_urls
        
        if word_count < 3 and num_urls == 0:
            logging.warning(f"Input is too short ({word_count} words) and has no URLs. Skipping model.")
            return jsonify({
                "prediction": "Legitimate",
                "confidence": 0.0,
                "reasons": ["Input is too short to analyze."]
            })
        
        # 5. Combine features
        X_comb = hstack([X_tfidf, X_lex])

        # 6. Get prediction
        pred_proba = clf.predict_proba(X_comb)[0]
        prediction_index = int(pred_proba.argmax())
        result_label = "Phishing" if prediction_index == 1 else "Legitimate"
        
        # 7. Get Explainable Reasons!
        reasons = get_prediction_reasons(X_lex, result_label)

        logging.info(f"Prediction: {result_label}, Confidence: {float(pred_proba[1]):.4f}")
        for reason in reasons:
            logging.info(f"  - Reason: {reason}")

        # 8. Return the full result + reasons
        return jsonify({
            "prediction": result_label,
            "confidence": float(pred_proba[1]), # Always send the PHISHING confidence
            "reasons": reasons # NEW: Send the list of reasons
        })

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        logging.exception("Stack trace:") # More detailed logging
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