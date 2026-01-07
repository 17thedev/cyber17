from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import os
from datetime import datetime

app = Flask(__name__)

# ---------------- CONFIG ----------------
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "confirm", "password", "bank",
    "wallet", "signin", "payment"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf"]

# ---------------- CORE LOGIC ----------------
def analyze_url(url: str):
    parsed = urlparse(url)
    issues = []
    score = 0

    if not parsed.scheme:
        issues.append("Missing URL scheme (http/https)")
        score += 2

    if parsed.scheme == "http":
        issues.append("Uses insecure HTTP")
        score += 2

    domain = parsed.netloc.lower()

    for word in PHISHING_KEYWORDS:
        if word in domain:
            issues.append(f"Suspicious keyword detected: {word}")
            score += 1

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            issues.append(f"Suspicious top-level domain: {tld}")
            score += 2

    if re.search(r"[0-9]", domain):
        issues.append("Domain contains numbers (possible impersonation)")
        score += 1

    if len(domain) > 35:
        issues.append("Unusually long domain name")
        score += 1

    if score >= 6:
        risk = "High"
    elif score >= 3:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "url": url,
        "risk": risk,
        "score": score,
        "issues": issues,
        "checked_at": datetime.utcnow().isoformat() + "Z"
    }

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = analyze_url(url)
    return jsonify(result)

@app.route("/scan", methods=["POST"])
def scan_ui():
    url = request.form.get("url", "").strip()
    result = analyze_url(url) if url else None
    return render_template("index.html", result=result)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    app.run(debug=True)
