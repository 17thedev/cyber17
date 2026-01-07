import os
import re
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request

app = Flask(__name__)

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "confirm", "password", "bank"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga"]
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


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

    if re.search(r"[0-9]", domain):
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

    return issues, risk


def save_report(url, issues, risk):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"{REPORT_DIR}/scan_{ts}.txt"

    with open(path, "w") as f:
        f.write(f"URL: {url}\n")
        f.write(f"Risk: {risk}\n")
        f.write("Issues:\n")
        for issue in issues:
            f.write(f"- {issue}\n")


@app.route("/", methods=["GET", "POST"])
def index():
    issues = None
    risk = None

    if request.method == "POST":
        url = request.form.get("url")
        issues, risk = analyze_url(url)
        save_report(url, issues, risk)

    return render_template("index.html", issues=issues, risk=risk)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

