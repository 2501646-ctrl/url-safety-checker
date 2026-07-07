import re
from urllib.parse import urlparse

# Known safe/trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'wikipedia.org', 'linkedin.com'
]

# Suspicious keywords often used in phishing links
SUSPICIOUS_KEYWORDS = [
    'verify', 'login', 'account', 'update', 'secure', 'confirm',
    'bank', 'signin', 'password', 'suspend'
]


def check_url_safety(url):
    score = 0
    warnings = []

    # Parse the URL into parts
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Check 1: Is it a trusted domain?
    for trusted in TRUSTED_DOMAINS:
        if trusted in domain:
            return "Safe", 0, ["This is a well-known trusted domain."]

    # Check 2: Does it use HTTPS?
    if parsed.scheme != 'https':
        score += 2
        warnings.append("Does not use HTTPS (not secure)")

    # Check 3: Is the domain an IP address instead of a name?
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        score += 3
        warnings.append("Uses an IP address instead of a domain name")

    # Check 4: Too many hyphens (common in fake domains)
    if domain.count('-') >= 2:
        score += 2
        warnings.append("Domain has an unusual number of hyphens")

    # Check 5: Suspicious keywords in the URL
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 1
            warnings.append(f"Contains suspicious keyword: '{keyword}'")

    # Check 6: URL length
    if len(url) > 75:
        score += 1
        warnings.append("URL is unusually long")

    # Check 7: Too many subdomains (e.g. secure.login.paypal.fake.com)
    if domain.count('.') >= 3:
        score += 2
        warnings.append("Domain has too many subdomains")

    # Final rating
    if score == 0:
        rating = "Safe"
    elif score <= 3:
        rating = "Low Risk"
    elif score <= 6:
        rating = "Suspicious"
    else:
        rating = "High Risk"

    return rating, score, warnings


# Test it
if __name__ == "__main__":
    test_url = input("Enter a URL to check: ")
    rating, score, warnings = check_url_safety(test_url)

    print(f"\nRating: {rating} (Risk Score: {score})")
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"- {w}")