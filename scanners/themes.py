import requests
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

from cve.cve_mapper import map_plugin_to_cves
from utils.risk_score import calculate_risk_score

# =========================
# CONFIG
# =========================

COMMON_THEMES = [
    "astra",
    "generatepress",
    "hello-elementor",
    "twentytwentythree",
    "twentytwentytwo",
    "twentytwentyone",
    "oceanwp",
    "kadence",
    "neve",
    "divi"
]

HEADERS = {
    "User-Agent": "Exp0siveLINE8pro-Scanner/1.0"
}

TIMEOUT = 8
MAX_WORKERS = 6

# =========================
# HELPERS
# =========================

def fetch(url):
    try:
        r = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )
        return r
    except Exception:
        return None


def valid_response(r):
    if not r:
        return False
    if r.status_code not in [200, 403]:
        return False
    if len(r.text) < 40:
        return False
    return True


def base_result(theme):
    return {
        "name": theme,
        "detected": False,
        "version": None,
        "risk": "UNKNOWN",
        "confidence": 0.0,
        "detection_method": [],
        "cves": [],
        "evidence": []
    }

# =========================
# VERSION EXTRACTION
# =========================

def extract_version_from_style_css(text):
    m = re.search(r"Version:\s*([0-9\.]+)", text, re.I)
    return m.group(1) if m else None


def extract_theme_from_html(html):
    """
    Extract active theme from HTML paths:
    /wp-content/themes/{theme}/
    """
    matches = re.findall(r"/wp-content/themes/([a-zA-Z0-9\-_]+)/", html)
    return list(set(matches))


def extract_version_from_html(html, theme):
    pattern = rf"{theme}.*?\?ver=([0-9\.]+)"
    m = re.search(pattern, html, re.I)
    return m.group(1) if m else None

# =========================
# CORE SCAN
# =========================

def scan_theme(base_url, theme, homepage_html):
    result = base_result(theme)

    theme_dir = f"/wp-content/themes/{theme}/"
    dir_url = urljoin(base_url, theme_dir)

    r = fetch(dir_url)
    if not valid_response(r):
        return None

    # Detected by directory
    result["detected"] = True
    result["confidence"] += 0.3
    result["detection_method"].append("directory_check")
    result["evidence"].append(theme_dir)

    # Version from HTML
    v = extract_version_from_html(homepage_html, theme)
    if v:
        result["version"] = v
        result["confidence"] += 0.3
        result["detection_method"].append("html_version")

    # style.css
    if not result["version"]:
        style_url = urljoin(base_url, theme_dir + "style.css")
        r_style = fetch(style_url)
        if r_style and r_style.status_code == 200:
            v = extract_version_from_style_css(r_style.text)
            if v:
                result["version"] = v
                result["confidence"] += 0.4
                result["detection_method"].append("style_css")

    # CVE Mapping (themes treated same as plugins)
    cves = map_plugin_to_cves(theme, result["version"])
    result["cves"] = cves

    # Risk Score
    result["risk"] = calculate_risk_score(result["version"], cves)

    if result["confidence"] > 1.0:
        result["confidence"] = 1.0

    return result

# =========================
# MAIN ENTRY
# =========================

def scan_themes(target_url):
    print("[*] Scanning WordPress themes (passive mode)...")

    homepage = fetch(target_url)
    homepage_html = homepage.text if homepage else ""

    results = []

    # Extract active themes dynamically
    detected_themes = extract_theme_from_html(homepage_html)

    # Merge with common list
    theme_list = list(set(detected_themes + COMMON_THEMES))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        tasks = [
            executor.submit(scan_theme, target_url, theme, homepage_html)
            for theme in theme_list
        ]

        for task in tasks:
            data = task.result()
            if data and data["detected"]:
                results.append(data)
                print(
                    f"[+] Theme: {data['name']} | "
                    f"v:{data['version']} | "
                    f"risk:{data['risk']} | "
                    f"conf:{data['confidence']}"
                )

    return results
