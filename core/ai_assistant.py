# core/ai_assistant.py

from core.decision_engine import ScanContext, Decision


class AIAssistant:
    def analyze_context(self, ctx: ScanContext, decision: Decision):
        print("\n[AI ASSISTANT]")
        print(f"Target: {ctx.target}")
        print(f"CMS: {ctx.cms}")
        print(f"Scan Mode Selected: {ctx.mode.value.upper()}")
        print(f"Decision: {decision.value}")

        if decision == Decision.ESCALATE:
            print("Reason: High-risk indicators detected")
        elif decision == Decision.REDUCE:
            print("Reason: Defensive mechanisms detected")
        else:
            print("Reason: Standard risk profile")

        if ctx.waf_detected:
            print("Advice: Avoid noisy payloads")
        if ctx.cms == "wordpress":
            print("Advice: Focus on plugin and theme exposure")

        print("[AI END]\n")
