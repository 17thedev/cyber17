from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "confirm", "password", "bank"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga"]

def analyze_url(url):
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
            issues.append(f"Phishing keyword detected: {word}")
            score += 1

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            issues.append(f"Suspicious top-level domain: {tld}")
            score += 2

    if re.search(r"\d", domain):
        issues.append("Domain contains numbers (possible impersonation)")
        score += 1

    if len(domain) > 35:
        issues.append("Domain length unusually long")
        score += 1

    if score <= 2:
        risk = "Low"
    elif score <= 5:
        risk = "Medium"
    else:
        risk = "High"

    return risk, score, issues


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")
        risk, score, issues = analyze_url(url)

        result = {
            "url": url,
            "risk": risk,
            "score": score,
            "issues": issues
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run()
