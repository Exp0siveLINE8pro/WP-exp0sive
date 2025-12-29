import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
RULES_DIR = BASE_DIR / "rules"

def load_rules(filename):
    path = RULES_DIR / filename
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_plugin_signatures(plugins):
    rules = load_rules("plugins.json")
    findings = []

    for plugin in plugins:
        for rule in rules:
            if plugin["name"] == rule["plugin"]:
                findings.append({
                    "component": plugin["name"],
                    "type": "plugin",
                    "signature": rule["id"],
                    "description": rule["description"],
                    "risk": rule["risk"],
                    "evidence": rule.get("evidence", [])
                })

    return findings

def run_wp_signatures(core):
    rules = load_rules("wordpress.json")
    findings = []

    for rule in rules:
        if rule["condition"] == "xmlrpc_enabled":
            if core.get("components", {}).get("xmlrpc", {}).get("enabled"):
                findings.append({
                    "component": "wordpress-core",
                    "type": "core",
                    "signature": rule["id"],
                    "description": rule["description"],
                    "risk": rule["risk"],
                    "evidence": ["xmlrpc.php enabled"]
                })

    return findings

def run_header_signatures(headers):
    rules = load_rules("headers.json")
    findings = []

    missing = headers.get("missing", {})
    for rule in rules:
        if rule["header"] in missing:
            findings.append({
                "component": "headers",
                "type": "headers",
                "signature": rule["id"],
                "description": rule["description"],
                "risk": rule["risk"],
                "evidence": [rule["header"]]
            })

    return findings
