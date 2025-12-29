import requests

HEADERS = {
    "User-Agent": "Exp0siveLINE8pro-Scanner/1.0"
}
TIMEOUT = 8

REQUIRED_HEADERS = {
    "Content-Security-Policy": "Controls resources loading",
    "Strict-Transport-Security": "Forces HTTPS",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer info",
    "Permissions-Policy": "Restricts browser features"
}

def fetch(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

def scan_headers(target_url):
    print("[*] Scanning security headers...")
    result = {
        "present": {},
        "missing": {},
        "risk": "LOW"
    }

    r = fetch(target_url)
    if not r:
        result["risk"] = "UNKNOWN"
        return result

    headers = {k.lower(): v for k, v in r.headers.items()}

    missing_count = 0
    for h, desc in REQUIRED_HEADERS.items():
        if h.lower() in headers:
            result["present"][h] = headers[h.lower()]
        else:
            result["missing"][h] = desc
            missing_count += 1

    if missing_count >= 4:
        result["risk"] = "HIGH"
    elif missing_count >= 2:
        result["risk"] = "MEDIUM"

    return result
