from cve.cve_fetcher import fetch_cves

def map_plugin_to_cves(plugin_name, version=None):
    cves = fetch_cves(plugin_name)
    mapped = []

    for item in cves:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        mapped.append({
            "cve_id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value"),
            "cvss": cvss
        })

    return mapped
