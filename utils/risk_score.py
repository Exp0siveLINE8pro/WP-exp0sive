def calculate_risk_score(version, cves):
    score = 0

    if not version:
        score += 2

    for cve in cves:
        if cve["cvss"]:
            if cve["cvss"] >= 9:
                score += 5
            elif cve["cvss"] >= 7:
                score += 3
            elif cve["cvss"] >= 4:
                score += 1

    if score >= 7:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    return "LOW"
