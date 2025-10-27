"""
ml_model.py

Loads the trained model and TF-IDF vectorizer from ../models/
Provides a small class (PhishMLModel) with:
 - predict(text) -> dict { is_phishing, confidence }
 - predict_proba(texts) -> list of probabilities
 - top_tfidf_tokens(text, topn) -> list of (token, score)

Uses joblib for loading (compatible with scikit-learn joblib.dump).
"""

import os
import re
import joblib
import numpy as np

from scipy.sparse import hstack

# Resolve paths relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # detection_engine/..
MODELS_DIR = os.path.join(BASE_DIR, "models")
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")
DEFAULT_TFIDF_PATH = os.path.join(MODELS_DIR, "tfidf.pkl")


class ModelLoadError(RuntimeError):
    pass


class PhishMLModel:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, tfidf_path: str = DEFAULT_TFIDF_PATH):
        # Validate files
        if not os.path.exists(model_path):
            raise ModelLoadError(f"Model file not found: {model_path}")
        if not os.path.exists(tfidf_path):
            raise ModelLoadError(f"TF-IDF file not found: {tfidf_path}")

        # Load artifacts
        self.model = joblib.load(model_path)
        self.tfidf = joblib.load(tfidf_path)

        # If model is a pipeline that already includes tfidf, this still works,
        # but later methods assume separate tfidf + numeric features can be stacked.
        # We'll detect behavior where needed.
        # Determine number of tfidf features (if possible)
        try:
            self.tfidf_feature_count = len(self.tfidf.get_feature_names_out())
        except Exception:
            # Older scikit-learn versions may not have get_feature_names_out
            try:
                self.tfidf_feature_count = len(self.tfidf.get_feature_names())
            except Exception:
                self.tfidf_feature_count = None

    # --- text cleaning method (same as training) ---
    @staticmethod
    def _clean_text(text: str) -> str:
        text = str(text or "")
        text = text.lower()
        text = re.sub(r"http\S+|www\S+|https\S+", " ", text)
        text = re.sub(r"\d+", " ", text)
        text = re.sub(r"[^a-z\s]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    # --- lexical features method (keeps parity with training lexical features) ---
    @staticmethod
    def _lexical_features(texts):
        URL_RE = re.compile(r"https?://[^\s]+", re.I)
        SUSPICIOUS_WORDS = [
            "urgent", "reset password", "click here", "verify", "confirm",
            "limited time", "action required", "security alert", "password"
        ]
        feats = []
        for text in texts:
            num_urls = len(URL_RE.findall(text))
            lower = text.lower()
            num_susp = sum(lower.count(w) for w in SUSPICIOUS_WORDS)
            num_upper_words = sum(1 for w in text.split() if w.isupper() and len(w) > 1)
            words = re.findall(r"\w+", text)
            avg_word_len = float(np.mean([len(w) for w in words])) if words else 0.0
            feats.append([num_urls, num_susp, num_upper_words, avg_word_len])
        return np.array(feats, dtype=float)

    # --- single-text prediction wrapper ---
    def predict(self, text: str):
        """
        Predict a single text. Returns:
        { "is_phishing": bool, "confidence": float }
        """
        cleaned = self._clean_text(text)
        # TF-IDF transform
        tfidf_vec = self.tfidf.transform([cleaned])

        # Lexical numeric features
        lex = self._lexical_features([text])

        # Many of our training pipelines stacked tfidf + lex numeric features horizontally.
        try:
            X = hstack([tfidf_vec, lex])
        except Exception:
            # If stacking fails (e.g., tfidf_vec is dense), convert lex to sparse accordingly
            from scipy import sparse
            X = hstack([tfidf_vec, sparse.csr_matrix(lex)])

        # Predict probability if available
        if hasattr(self.model, "predict_proba"):
            proba = float(self.model.predict_proba(X)[:, 1][0])
        else:
            # fallback to decision function or predict
            if hasattr(self.model, "decision_function"):
                score = float(self.model.decision_function(X)[0])
                # convert to pseudo-proba via sigmoid
                proba = 1.0 / (1.0 + np.exp(-score))
            else:
                proba = float(self.model.predict(X)[0])

        pred = bool(proba >= 0.5)
        return {"is_phishing": pred, "confidence": round(proba, 4)}

    # --- batch predict_proba for lists of texts ---
    def predict_proba(self, texts):
        cleaned = [self._clean_text(t) for t in texts]
        tfidf_vec = self.tfidf.transform(cleaned)
        lex = self._lexical_features(texts)
        try:
            X = hstack([tfidf_vec, lex])
        except Exception:
            from scipy import sparse
            X = hstack([tfidf_vec, sparse.csr_matrix(lex)])

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)[:, 1]
            return [float(p) for p in probs]
        else:
            if hasattr(self.model, "decision_function"):
                scores = self.model.decision_function(X)
                probs = 1.0 / (1.0 + np.exp(-scores))
                return [float(p) for p in probs]
            else:
                preds = self.model.predict(X)
                return [float(p) for p in preds]

    # --- explainability: top TF-IDF tokens contributing positively ---
    def top_tfidf_tokens(self, text: str, topn: int = 5):
        """
        Returns list of tuples (token, score) sorted by highest positive contribution.
        Works best with linear models (LogisticRegression) where coef_ exists.
        """
        cleaned = self._clean_text(text)
        tfidf_vec = self.tfidf.transform([cleaned])
        # Get feature names
        try:
            fnames = list(self.tfidf.get_feature_names_out())
        except Exception:
            try:
                fnames = list(self.tfidf.get_feature_names())
            except Exception:
                fnames = None

        if fnames is None or not hasattr(self.model, "coef_"):
            return []

        # Coefficients correspond to tfidf features first (if model trained that way)
        coefs = self.model.coef_[0][: len(fnames)]
        arr = tfidf_vec.toarray()[0]
        token_scores = {}
        for i, val in enumerate(arr):
            if val > 0:
                token_scores[fnames[i]] = val * coefs[i]
        top = sorted(token_scores.items(), key=lambda kv: kv[1], reverse=True)[:topn]
        return top


# Simple CLI test when running file directly
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--tfidf", default=DEFAULT_TFIDF_PATH)
    parser.add_argument("--text", default="Urgent: reset your password by clicking http://fake.example now")
    args = parser.parse_args()

    # load with custom paths if provided
    m = PhishMLModel(args.model, args.tfidf)
    print("Model loaded. Testing predict()")
    print(m.predict(args.text))
    print("Top tokens:", m.top_tfidf_tokens(args.text))
