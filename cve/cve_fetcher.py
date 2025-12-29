import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "Exp0siveLINE8pro"
}

def fetch_cves(keyword, max_results=5):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        r = requests.get(NVD_API, headers=HEADERS, params=params, timeout=10)
        if r.status_code == 200:
            return r.json().get("vulnerabilities", [])
    except Exception:
        pass

    return []
