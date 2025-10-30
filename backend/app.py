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
    logging.info(f"Loaded model metadata: {meta}")
    
    logging.info("\n--- Artifacts loaded successfully ---")

except FileNotFoundError as e:
    logging.error(f"CRITICAL ERROR: Model file not found. {e}")
    logging.error("Please make sure 'model.pkl', 'tfidf.pkl', and 'model_meta.json' are in the 'models' directory.")
    clf = None
    tfidf = None
    meta = None
except Exception as e:
    logging.error(f"An unexpected error occurred during model loading: {e}")
    clf = None
    tfidf = None
    meta = None


# --- Feature Extraction Functions (Copied from training) ---

# This is the helper that cleans text for TF-IDF
# This regex is simple on purpose, to not remove link-like words from TF-IDF
url_re_simple = re.compile(r"http\S+|https\S+", flags=re.I)
def clean_text(s):
    s = str(s)
    s = s.lower()
    # We ONLY remove full http links from the text.
    # We LEAVE 'gogle.com' and 'www.gogle.com' for the TF-IDF to see.
    s = url_re_simple.sub(" ", s) 
    s = re.sub(r"\d+", " ", s)  # remove digits
    s = re.sub(r"[^a-z\s]", " ", s) # keep letters + space
    s = re.sub(r"\s+", " ", s).strip() # normalize whitespace
    return s

# These are the lexical features
suspicious_list = [
    "urgent", "reset password", "click here", "verify", "confirm",
    "limited time", "action required", "security alert", "password", "bank", "transfer",
    "account", "login", "invoice", "payment", "due"
]
susp_re = re.compile("|".join([re.escape(s) for s in suspicious_list]), flags=re.I)

# This is the GOOD, smart URL finder for the lexical features
url_finder = re.compile(r"(?:https?://|www\.|[a-zA-Z0-9-]+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", flags=re.I)

def lexical_feats_from_raw_texts(raw_texts):
    feats = []
    for txt in raw_texts:
        t = str(txt)
        num_urls = len(url_finder.findall(t))
        num_susp = len(susp_re.findall(t))
        num_upper = sum(1 for w in t.split() if w.isupper() and len(w) > 1)
        words = re.findall(r"\w+", t)
        avg_len = float(np.mean([len(w) for w in words])) if words else 0.0
        feats.append([num_urls, num_susp, num_upper, avg_len])
    return np.array(feats, dtype=float)

# This function combines all features
def extract_features(raw_texts_list):
    """
    Extracts combined TF-IDF and Lexical features.
    Returns:
        - X_comb: Combined sparse matrix for the model
        - cleaned_texts: List of cleaned text strings
        - X_lex: The numpy array of lexical features
    """
    # 1. Clean text for TF-IDF
    cleaned_texts = [clean_text(t) for t in raw_texts_list]
    
    # 2. Apply saved TF-IDF
    X_tfidf = tfidf.transform(cleaned_texts)
    
    # 3. Get lexical features (from RAW text)
    X_lex = lexical_feats_from_raw_texts(raw_texts_list)
    
    # 4. Combine
    X_comb = hstack([X_tfidf, X_lex])
    return X_comb, cleaned_texts, X_lex


# --- Prediction Endpoint ---
@app.route("/predict", methods=["POST"])
def predict_endpoint():
    if clf is None or tfidf is None:
        return jsonify({"error": "Model is not loaded. Check server logs."}), 500

    data = request.json
    text = data.get("text", "")
    
    if not text:
        return jsonify({"error": "No text provided"}), 400

    logging.info(f"Received text for analysis: {text[:70]}...")

    try:
        # 1. Extract features AND get the cleaned text back
        features_comb, cleaned_texts, lex_features = extract_features([text])
        
        # *** THE REAL FIX (V3) ***
        # Get num_urls from the lexical features (it's the first column)
        num_urls = lex_features[0, 0] 
        
        # Get word count from the *cleaned* text
        cleaned_input = cleaned_texts[0]
        word_count = len(cleaned_input.split())
        
        # We only skip if the text is short AND it has NO URLs.
        # This will now analyze "gogle.com" (word_count=2, num_urls=1)
        # It will skip "link" (word_count=1, num_urls=0)
        if word_count < 3 and num_urls == 0:
            logging.warning(f"Input is too short ({word_count} words) and has no URLs. Skipping model.")
            return jsonify({
                "prediction": "Legitimate", # Default to safe
                "confidence": 0.0, # 0% phishing confidence
                "message": "Input is too short to analyze."
            })

        # 2. Get prediction probabilities
        # pred_proba will be like [0.98, 0.02] (prob_legitimate, prob_phishing)
        pred_proba = clf.predict_proba(features_comb)[0]
        
        # 3. Get the prediction (0 or 1)
        prediction_index = int(pred_proba.argmax())
        
        # 4. Get the confidence for that prediction
        confidence = float(pred_proba[prediction_index])
        
        # 5. Get the label
        result_label = "Phishing" if prediction_index == 1 else "Legitimate"

        logging.info(f"Prediction: {result_label}, Confidence: {float(pred_proba[1]):.4f}")

        # 6. Return the full result
        # Note: The frontend wants the 'phishing' confidence, so we send pred_proba[1]
        return jsonify({
            "prediction": result_label,
            "confidence": float(pred_proba[1]) # Always send the PHISHING confidence
        })

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
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
    # Use 0.0.0.0 to make it accessible on your network
    # Debug=True makes it auto-reload when you save the file
    app.run(host="0.0.0.0", port=5001, debug=True)