import re

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "password", "account suspended", "click here",
    "confirm", "reset", "update", "login", "security alert", "bank"
]

def check_suspicious_phrases(text):
    alerts = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{keyword}\b", text, re.IGNORECASE):
            alerts.append(keyword)
    return alerts
