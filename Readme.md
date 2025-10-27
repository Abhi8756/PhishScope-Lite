# PhishScope Lite

PhishScope Lite — a hybrid cybersecurity + ML project: lightweight phishing detector using heuristics (regex), TF-IDF + logistic regression, and domain analysis. Built as a FastAPI backend and React frontend to demonstrate end-to-end pipeline.

## Features
- Regex heuristic flags (suspicious phrases, IP-in-URL, attachment hints)
- ML classifier (TF-IDF + lexical features) trained in Colab/Kaggle
- Domain analysis (tldextract + whois) for URL enrichment (optional)
- FastAPI REST endpoint `/predict`
- React frontend to paste emails and receive explainable results

## Tech stack
- Backend: Python, FastAPI, scikit-learn
- Frontend: React
- Model training: Colab / Kaggle
- Optional DB: MongoDB for storing reports

## Quickstart (local)
1. Train or copy model files to `backend/models/model.pkl` and `backend/models/tfidf.pkl`. See `notebooks/training.ipynb`.
2. Install backend deps:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn app:app --reload
