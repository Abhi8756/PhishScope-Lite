import joblib
import re
import numpy as np
from scipy.sparse import hstack
import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS # Import CORS

# ---------------------------
# App Setup
# ---------------------------
app = Flask(__name__)
# Enable CORS for all routes, allowing your React app (from any origin)
CORS(app) 

# ---------------------------
# CONFIG
# ---------------------------
# Path to the models folder (assumed to be in the same dir as app.py)
MODELS_DIR = "models" 
MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")
TFIDF_PATH = os.path.join(MODELS_DIR, "tfidf.pkl")
META_PATH = os.path.join(MODELS_DIR, "model_meta.json")

# ---------------------------
# 1) LOAD ARTIFACTS
# ---------------------------
print(f"Loading model from {MODEL_PATH}")
print(f"Loading tfidf from {TFIDF_PATH}")

try:
    clf = joblib.load(MODEL_PATH)
    tfidf = joblib.load(TFIDF_PATH)
except FileNotFoundError as e:
    print("---")
    print(f"ERROR: Model file not found at {e.filename}")
    print("Please make sure 'model.pkl' and 'tfidf.pkl' exist in the 'backend/models' folder.")
    print("---")
    exit(1) # Exit if models aren't found

if os.path.exists(META_PATH):
    with open(META_PATH, 'r') as f:
        meta = json.load(f)
    print("Loaded model metadata:", meta)
    # Check sklearn version
    try:
        import sklearn
        if meta.get("sklearn_version") and meta["sklearn_version"] != sklearn.__version__:
            print(f"--- WARNING ---")
            print(f"Model trained with sklearn {meta['sklearn_version']}, but you have {sklearn.__version__} installed.")
            print("This may cause issues. If you see errors, install the exact version:")
            print(f"pip install scikit-learn=={meta['sklearn_version']}")
            print(f"---------------")
    except ImportError:
        pass # sklearn not installed? (should be, via requirements)
else:
    print("Warning: model_meta.json not found. Continuing without metadata.")

print("\n--- Artifacts loaded successfully ---")

# ---------------------------
# 2) DEFINE FEATURE FUNCTIONS
# (Must be identical to training script)
# ---------------------------

# Text cleaning function
url_re = re.compile(r"http\S+|www\S+|https\S+", flags=re.I)
def clean_text(s):
    s = str(s)
    s = s.lower()
    s = url_re.sub(" ", s)          # remove URLs
    s = re.sub(r"\d+", " ", s)      # remove digits
    s = re.sub(r"[^a-z\s]", " ", s) # keep letters + space
    s = re.sub(r"\s+", " ", s).strip() # normalize whitespace
    return s

# Lexical feature extraction function
suspicious_list = [
    "urgent", "reset password", "click here", "verify", "confirm",
    "limited time", "action required", "security alert", "password", "bank", "transfer"
]
susp_re = re.compile("|".join([re.escape(s) for s in suspicious_list]), flags=re.I)
url_finder = re.compile(r"httpsS?://[^\s]+", flags=re.I)

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

# ---------------------------
# 3) PREDICTION FUNCTION
# ---------------------------

def predict_email_text(raw_text):
    """
    Takes a single raw email text string and returns the prediction.
    """
    # 1. Put the single text into a list (models expect a batch)
    raw_text_list = [raw_text]

    # 2. Clean the text
    cleaned_text_list = [clean_text(raw_text)]

    # 3. Extract TF-IDF features from CLEANED text
    X_tfidf = tfidf.transform(cleaned_text_list)

    # 4. Extract lexical features from RAW text
    X_lex = lexical_feats_from_raw_texts(raw_text_list)

    # 5. Combine features
    X_comb = hstack([X_tfidf, X_lex])

    # 6. Make prediction
    pred = clf.predict(X_comb)
    proba = clf.predict_proba(X_comb)

    # 7. Return the first (and only) prediction and its probabilities
    # pred[0] will be 0 (Legit) or 1 (Phishing)
    # proba[0] will be [prob_legit, prob_phish]
    return pred[0], proba[0]

# ---------------------------
# 4) DEFINE API ENDPOINT
# ---------------------------

@app.route("/predict", methods=["POST"])
def handle_predict():
    if not request.json or 'text' not in request.json:
        return jsonify({"error": "No 'text' field provided"}), 400

    try:
        raw_text = request.json['text']
        
        # 1. Make the prediction
        prediction_code, probabilities = predict_email_text(raw_text)
        
        # 2. Convert to human-readable format
        # 0 = Legitimate, 1 = Phishing
        
        prob_legit = probabilities[0]
        prob_phish = probabilities[1]
        
        if prediction_code == 1:
            result_label = "PHISHING"
            confidence = prob_phish
        else:
            result_label = "LEGITIMATE"
            confidence = prob_legit

        # 3. Send the response
        response = {
            "prediction": result_label,
            # Format confidence as a percentage string, e.g., "97.23%"
            "confidence": f"{confidence * 100:.2f}%", 
            "scores": {
                "legitimate": prob_legit,
                "phishing": prob_phish
            }
        }
        return jsonify(response)

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({"error": "Prediction failed", "details": str(e)}), 500

# ---------------------------
# 5) RUN THE APP
# ---------------------------
if __name__ == "__main__":
    # Host='0.0.0.0' makes it accessible on your network
    # Port=5001 is a good choice to avoid conflicts with React (3000)
    print("Starting Flask server on http://127.0.0.1:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)

