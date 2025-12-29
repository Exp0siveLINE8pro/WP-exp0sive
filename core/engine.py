from scanners.wp_core import scan_wp_core
from scanners.plugins import scan_plugins
from scanners.themes import scan_themes
from scanners.headers import scan_headers
from scanners.misconfig import scan_misconfig
from core.ai_assistant import analyze_with_ai

class ScannerEngine:
    def __init__(self, target, use_ai=False):
        self.target = target
        self.use_ai = use_ai
        self.results = {}

    def run(self):
        self.results["core"] = scan_wp_core(self.target)
        self.results["plugins"] = scan_plugins(self.target)
        self.results["themes"] = scan_themes(self.target)
        self.results["headers"] = scan_headers(self.target)
        self.results["misconfig"] = scan_misconfig(self.target)

        if self.use_ai:
            self.results["ai_analysis"] = analyze_with_ai(self.results)

        return self.results

    def save_report(self, path):
        import json
        with open(path, "w") as f:
            json.dump(self.results, f, indent=4)
