import requests
from urllib.parse import urljoin

HEADERS = {
    "User-Agent": "Exp0siveLINE8pro-Scanner/1.0"
}
TIMEOUT = 8

SENSITIVE_PATHS = [
    ".env",
    "wp-config.php~",
    "wp-config.php.bak",
    "backup.zip",
    "backup.sql",
    ".git/config",
    ".htaccess",
]

DIRECTORY_CHECKS = [
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-content/themes/"
]

def fetch(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        return None

def is_directory_listing(text):
    indicators = ["Index of /", "<title>Index of"]
    return any(i in text for i in indicators)

def scan_misconfig(target_url):
    print("[*] Scanning misconfigurations...")
    result = {
        "exposed_files": [],
        "directory_listing": [],
        "risk": "LOW"
    }

    # Sensitive files
    for path in SENSITIVE_PATHS:
        url = urljoin(target_url, "/" + path)
        r = fetch(url)
        if r and r.status_code == 200 and len(r.text) > 20:
            result["exposed_files"].append(path)

    # Directory listing
    for d in DIRECTORY_CHECKS:
        url = urljoin(target_url, d)
        r = fetch(url)
        if r and r.status_code == 200 and is_directory_listing(r.text):
            result["directory_listing"].append(d)

    # Risk calculation
    score = len(result["exposed_files"]) * 2 + len(result["directory_listing"])
    if score >= 4:
        result["risk"] = "CRITICAL"
    elif score >= 2:
        result["risk"] = "HIGH"
    elif score == 1:
        result["risk"] = "MEDIUM"

    return result
