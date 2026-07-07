# URL/Link Safety Checker

A Python tool that analyzes URLs for common phishing and scam indicators.

## Features
- Detects suspicious keywords (verify, login, secure, etc.)
- Flags IP addresses used instead of domain names
- Checks for HTTPS usage
- Detects excessive subdomains and hyphens
- Whitelists well-known trusted domains

## Tech Stack
Python, Streamlit, Regex, urllib

## How to Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
```

## What I Learned
This project helped me understand the common patterns used in phishing links — things like IP-based URLs, excessive subdomains, and urgency-related keywords that attackers use to trick users.
