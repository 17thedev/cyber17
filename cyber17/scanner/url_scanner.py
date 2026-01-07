import re
import socket
import requests
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account",
    "update", "free", "bonus", "confirm", "bank"
]

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False

def scan_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # HTTPS check
    if not url.startswith("https://"):
        score += 2
        reasons.append("Website does not use HTTPS")

    # IP address check
    if is_ip_address(domain):
        score += 3
        reasons.append("URL uses IP address instead of domain")

    # Keyword check
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword detected: {word}")

    # URL length
    if len(url) > 75:
        score += 1
        reasons.append("Unusually long URL")

    # Typosquatting check
    extracted = tldextract.extract(domain)
    if len(extracted.domain) < 4:
        score += 1
        reasons.append("Suspicious domain structure")

    # Final verdict
    if score >= 5:
        status = "Dangerous"
    elif score >= 3:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "status": status,
        "score": score,
        "reasons": reasons
    }