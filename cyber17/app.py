from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import os
from datetime import datetime

app = Flask(__name__)

# ---------------- CONFIG ----------------
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "confirm", "password", "bank"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga"]

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# ---------------- LOGIC ----------------
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
            issues.append(f"Phishing keyword detected: '{word}'")
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
v
    risk = "Low"
    if score >= 5:
        risk = "High"
    elif score >= 3:
        risk = "Medium"

    return issues, risk

def save_report(url, issues, risk):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{REPORT_DIR}/scan_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("Cyber17 Scan Report\n")
        f.write("=" * 30 + "\n")
        f.write(f"URL: {url}\n")
        f.write(f"Risk Level: {risk}\n\n")
        f.write("Issues Detected:\n")

        if issues:
            for issue in issues:
                f.write(f"- {issue}\n")
        else:
            f.write("- No obvious threats detected\n")

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk = None

    if request.method == "POST":
        url = request.form.get("url")
        result, risk = analyze_url(url)
        save_report(url, result, risk)

    return render_template("index.html", result=result, risk=risk)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)



# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
# ---------------- ROUTES ----------------
from flask import render_template

def save_report(url, issues, risk):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{REPORT_DIR}/scan_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("Cyber17 Scan Report\n")
        f.write("=" * 30 + "\n")
        f.write(f"URL: {url}\n")
        f.write(f"Risk Level: {risk}\n\n")
        f.write("Issues Detected:\n")

        if issues:
            for issue in issues:
                f.write(f"- {issue}\n")
        else:
            f.write("- No obvious threats detected\n")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk = None

    if request.method == "POST":
        url = request.form.get("url")
        result, risk = analyze_url(url)
        save_report(url, result, risk)

    return render_template("index.html", result=result, risk=risk)


# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
