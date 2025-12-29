# core/decision_engine.py

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List


class ScanMode(Enum):
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    DEEP = "deep"


class Decision(Enum):
    CONTINUE = "continue"
    ESCALATE = "escalate"
    REDUCE = "reduce"
    ABORT = "abort"


@dataclass
class ScanContext:
    target: str
    cms: str = None
    waf_detected: bool = False
    headers: Dict = field(default_factory=dict)
    plugins: List[str] = field(default_factory=list)
    cves: List[Dict] = field(default_factory=list)
    response_anomalies: bool = False
    rate_limited: bool = False
    risk_score: int = 0
    mode: ScanMode = ScanMode.NORMAL


class DecisionEngine:
    def __init__(self, context: ScanContext):
        self.ctx = context
        self.decisions: List[str] = []

    def evaluate(self) -> Decision:
        """
        Main decision point
        """
        # Kill switch
        if self.ctx.rate_limited:
            self.ctx.mode = ScanMode.PASSIVE
            self.decisions.append("Rate-limit detected → switching to PASSIVE")
            return Decision.REDUCE

        # WAF logic
        if self.ctx.waf_detected:
            if self.ctx.response_anomalies:
                self.ctx.mode = ScanMode.PASSIVE
                self.decisions.append("WAF + anomalies → PASSIVE scan")
                return Decision.REDUCE

        # WordPress escalation
        if self.ctx.cms == "wordpress":
            if len(self.ctx.plugins) >= 5:
                self.ctx.mode = ScanMode.DEEP
                self.decisions.append("Multiple WP plugins → DEEP scan")
                return Decision.ESCALATE

        # Critical CVE escalation
        for cve in self.ctx.cves:
            if cve.get("severity") == "CRITICAL" and cve.get("public_exploit"):
                self.ctx.mode = ScanMode.AGGRESSIVE
                self.decisions.append(
                    f"Critical CVE {cve.get('id')} with exploit → AGGRESSIVE scan"
                )
                return Decision.ESCALATE

        # High risk score
        if self.ctx.risk_score >= 80:
            self.ctx.mode = ScanMode.AGGRESSIVE
            self.decisions.append("High risk score → AGGRESSIVE scan")
            return Decision.ESCALATE

        self.decisions.append("No special conditions → NORMAL scan")
        return Decision.CONTINUE

    def summary(self) -> Dict:
        return {
            "target": self.ctx.target,
            "scan_mode": self.ctx.mode.value,
            "decisions": self.decisions,
            "risk_score": self.ctx.risk_score
        }
