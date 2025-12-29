import json
import datetime
from pathlib import Path

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Exp0siveLINE8pro Report</title>
<style>
body {
  background: radial-gradient(circle at top, #0f2027, #000);
  color: #d0faff;
  font-family: Consolas, monospace;
}
h1,h2,h3 { color:#00ffd5; }
.container { width:92%; margin:auto; }
.card {
  background: rgba(5,20,30,0.9);
  border:1px solid #00ffd533;
  border-radius:10px;
  padding:16px;
  margin:14px 0;
  box-shadow:0 0 20px #00ffd522;
}
.badge {
  padding:4px 10px;
  border-radius:14px;
  font-weight:bold;
}
.CRITICAL { background:#ff0033; }
.HIGH { background:#ff6a00; }
.MEDIUM { background:#ffd000; color:#000; }
.LOW { background:#00c853; }
.UNKNOWN { background:#607d8b; }
pre {
  background:#050b14;
  padding:12px;
  border-radius:8px;
  overflow:auto;
}
</style>
</head>
<body>
<div class="container">
<h1>Exp0siveLINE8pro – Cyber Security Report</h1>
<p>Target: {{TARGET}} | Date: {{DATE}}</p>
{{CONTENT}}
</div>
</body>
</html>
"""

def badge(r):
    return f'<span class="badge {r}">{r}</span>'

def section(title, body):
    return f'<div class="card"><h2>{title}</h2>{body}</div>'

def kv(k, v):
    return f"<p><b>{k}:</b> {v}</p>"

def json_block(obj):
    return f"<pre>{json.dumps(obj, indent=2)}</pre>"

def build_html(target, results):
    parts = []

    ai = results.get("ai_analysis", {})
    ai_body = ""
    ai_body += kv("Global Risk Score", ai.get("global_risk_score"))
    ai_body += kv("Security Posture", badge(ai.get("posture", "UNKNOWN")))
    ai_body += "<h3>AI Insights</h3>" + json_block(ai.get("insights", []))
    parts.append(section("AI Security Analyst", ai_body))

    parts.append(section("Raw Scan Data", json_block(results)))

    html = HTML_TEMPLATE.replace("{{TARGET}}", target)\
        .replace("{{DATE}}", datetime.datetime.utcnow().isoformat())\
        .replace("{{CONTENT}}", "".join(parts))

    return html


def save_reports(target, results, out_dir="reports", basename="report"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    json_path = Path(out_dir) / f"{basename}_{ts}.json"
    html_path = Path(out_dir) / f"{basename}_{ts}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html(target, results))

    return str(json_path), str(html_path)
