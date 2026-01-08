# Machine Learning Folder (Design Only)

This folder documents the **planned machine learning component** of Cyber17.

⚠️ **Important clarification:**  
There is currently **no active machine learning code** running in production.
The phishing detection system in Cyber17 is **fully heuristic-based**.

---

## Purpose of This Folder

The `ml/` directory exists to:

- Explain how machine learning can be added in the future
- Show system design thinking
- Document a correct and safe upgrade path

This is **design documentation**, not executable code.

---

## Current Production Status

- Detection method: Heuristic rules
- Deployment: Flask application on Railway
- Machine learning: ❌ Not deployed

---

## Planned ML Upgrade (Future Work)

If Cyber17 is extended, machine learning will be added in phases:

1. Feature extraction from URLs  
   - Domain length  
   - HTTPS usage  
   - Keyword frequency  
   - Digit and hyphen counts  

2. Dataset preparation  
   - Phishing URLs
   - Legitimate URLs

3. Model training  
   - Logistic Regression or Random Forest

4. Hybrid scoring  
   - Combine heuristic score with ML confidence

---

## Reason for This Approach

In cybersecurity systems:

- Heuristics are faster and explainable
- ML models require validated data
- Hybrid systems are safer and more reliable

This folder exists to document that professional approach.
