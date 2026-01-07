from flask import Flask, render_template, request
from scanner.url_scanner import scan_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        result = scan_url(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000)
  