from fastapi import FastAPI
from pydantic import BaseModel
from detection_engine.ml_model import PhishMLModel
from detection_engine.regex_detector import check_suspicious_phrases
from detection_engine.domain_analysis import extract_domains

# Initialize FastAPI app
app = FastAPI(title="PhishScope Lite – Intelligent Email Phishing Detector")

# Load ML model
ml_detector = PhishMLModel("models/model.pkl", "models/tfidf.pkl")

# Input schema
class EmailInput(BaseModel):
    text: str

@app.get("/")
def root():
    return {"message": "Welcome to PhishScope Lite API 🔒"}

@app.post("/analyze")
def analyze_email(email: EmailInput):
    # Rule-based detection
    regex_flags = check_suspicious_phrases(email.text)
    domains = extract_domains(email.text)

    # ML-based detection
    ml_result = ml_detector.predict(email.text)

    return {
        "regex_alerts": regex_flags,
        "domains_found": domains,
        "ml_prediction": ml_result
    }
