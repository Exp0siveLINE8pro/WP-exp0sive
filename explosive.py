# core/engine.py

from core.http_client import HttpClient
from core.fingerprint import Fingerprinter
from core.reporter import Reporter
from core.ai_assistant import AIAssistant
from core.decision_engine import ScanContext, DecisionEngine
from utils.risk_score import calculate_risk


class ExplosiveEngine:
    def __init__(self, target: str):
        self.target = target
        self.http = HttpClient(target)
        self.fingerprint = Fingerprinter(self.http)
        self.reporter = Reporter(target)
        self.ai = AIAssistant()

    def run(self):
        headers = self.http.fetch_headers()
        cms, plugins = self.fingerprint.detect()

        risk = calculate_risk(cms, plugins)

        ctx = ScanContext(
            target=self.target,
            cms=cms,
            headers=headers,
            plugins=plugins,
            waf_detected=self.fingerprint.waf_detected,
            response_anomalies=self.http.anomalies,
            rate_limited=self.http.rate_limited,
            risk_score=risk
        )

        decision_engine = DecisionEngine(ctx)
        decision = decision_engine.evaluate()

        self.ai.analyze_context(ctx, decision)

        if decision.name == "ABORT":
            self.reporter.add_warning("Scan aborted by Decision Engine")
            return

        self.reporter.add_decision(decision_engine.summary())

        # Continue scan based on mode
        if ctx.mode.value in ["aggressive", "deep"]:
            self.run_deep_scan(ctx)
        else:
            self.run_basic_scan(ctx)

        self.reporter.generate()

    def run_basic_scan(self, ctx):
        self.reporter.add_info("Running BASIC scan")

    def run_deep_scan(self, ctx):
        self.reporter.add_info(f"Running {ctx.mode.value.upper()} scan")
