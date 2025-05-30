import re
import urllib.parse
import requests

# Suspicious keywords commonly used in phishing links
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'ebay', 'paypal']

def is_ip_address(url):
    return bool(re.match(r'https?://(\d{1,3}\.){3}\d{1,3}', url))

def has_suspicious_keywords(url):
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in url.lower():
            return True
    return False

def has_at_symbol(url):
    return '@' in url

def is_url_too_long(url, threshold=75):
    return len(url) > threshold

def has_dash_in_domain(url):
    domain = urllib.parse.urlparse(url).netloc
    return '-' in domain

def get_google_safebrowsing_verdict(api_key, url):
    safe_browsing_api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    body = {
        "client": {
            "clientId": "PhishingScanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(safe_browsing_api_url, json=body)
    if response.status_code == 200:
        return bool(response.json().get('matches'))
    else:
        print("Error contacting Safe Browsing API:", response.status_code)
        return False

def scan_url(url, api_key=None):
    print(f"\nScanning URL: {url}")
    warnings = []

    if is_ip_address(url):
        warnings.append("⚠️ Uses IP address instead of domain")
    if has_suspicious_keywords(url):
        warnings.append("⚠️ Contains suspicious keywords")
    if has_at_symbol(url):
        warnings.append("⚠️ Contains '@' symbol")
    if is_url_too_long(url):
        warnings.append("⚠️ URL is unusually long")
    if has_dash_in_domain(url):
        warnings.append("⚠️ Domain contains hyphen (-)")

    if api_key:
        if get_google_safebrowsing_verdict(api_key, url):
            warnings.append("🚨 Flagged by Google Safe Browsing!")

    if not warnings:
        print("✅ No immediate phishing traits detected.")
    else:
        for warn in warnings:
            print(warn)

if __name__ == "__main__":
    url = input("Enter URL to scan: ").strip()
    # Optional: Google API key
    # api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
    api_key = None
    scan_url(url, api_key)
