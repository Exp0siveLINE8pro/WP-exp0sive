import requests
import re
from urllib.parse import urljoin

from cve.cve_mapper import map_plugin_to_cves
from utils.risk_score import calculate_risk_score

HEADERS = {
    "User-Agent": "Exp0siveLINE8pro-Scanner/1.0"
}

TIMEOUT = 8


def fetch(url):
    try:
        return requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )
    except Exception:
        return None


def base_result():
    return {
        "is_wordpress": False,
        "version": None,
        "confidence": 0.0,
        "evidence": [],
        "components": {},
        "cves": [],
        "risk": "UNKNOWN"
    }


def detect_wp_from_html(html):
    indicators = ["wp-content", "wp-includes", "wordpress"]
    html = html.lower()
    return any(i in html for i in indicators)


def extract_version_from_meta(html):
    m = re.search(
        r'<meta name="generator" content="WordPress\s*([0-9\.]+)"',
        html,
        re.I
    )
    return m.group(1) if m else None


def extract_version_from_assets(html):
    m = re.search(r"wp-includes/.*?\?ver=([0-9\.]+)", html)
    return m.group(1) if m else None


def check_readme(base_url):
    r = fetch(urljoin(base_url, "/readme.html"))
    if r and r.status_code == 200 and "WordPress" in r.text:
        m = re.search(r"Version\s*([0-9\.]+)", r.text)
        return {"exposed": True, "version": m.group(1) if m else None}
    return {"exposed": False}


def check_xmlrpc(base_url):
    r = fetch(urljoin(base_url, "/xmlrpc.php"))
    return {"enabled": bool(r and r.status_code in [200, 405])}


def check_rest_api(base_url):
    r = fetch(urljoin(base_url, "/wp-json/"))
    return {"enabled": bool(r and r.status_code == 200)}


def check_debug_log(base_url):
    r = fetch(urljoin(base_url, "/wp-content/debug.log"))
    return {"exposed": bool(r and r.status_code == 200)}


# =========================
# 🔥 THIS IS WHAT IMPORT NEEDS
# =========================
def scan_wp_core(target_url):
    print("[*] Scanning WordPress core...")

    result = base_result()

    homepage = fetch(target_url)
    if not homepage:
        return result

    html = homepage.text

    if detect_wp_from_html(html):
        result["is_wordpress"] = True
        result["confidence"] += 0.4
        result["evidence"].append("html_wp_fingerprint")

    version = extract_version_from_meta(html)
    if not version:
        version = extract_version_from_assets(html)

    if version:
        result["version"] = version
        result["confidence"] += 0.3
        result["evidence"].append("version_detected")

    readme = check_readme(target_url)
    result["components"]["readme"] = readme
    if readme.get("version") and not result["version"]:
        result["version"] = readme["version"]

    result["components"]["xmlrpc"] = check_xmlrpc(target_url)
    result["components"]["rest_api"] = check_rest_api(target_url)
    result["components"]["debug_log"] = check_debug_log(target_url)

    if result["is_wordpress"]:
        cves = map_plugin_to_cves("wordpress", result["version"])
        result["cves"] = cves
        result["risk"] = calculate_risk_score(result["version"], cves)

    result["confidence"] = min(result["confidence"], 1.0)
    return result
