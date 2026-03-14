"""
Normalizer for suspicious prompt or unsafe input events.
"""
import re
from app.normalizers.common import build_base_incident
from api.schemas import SentinelIncident

SUSPICIOUS_PATTERNS = [
    (r"ignore previous instructions", 90, "instruction_override"),
    (r"reveal (secrets|api key|credentials)", 85, "data_exfiltration"),
    (r"exfiltrate", 80, "data_exfiltration"),
    (r"system prompt", 70, "policy_bypass")
]

def normalize_prompt_event(raw_event: dict) -> SentinelIncident:
    """
    Accepts: {"user_id": str, "prompt": str}
    """
    user_id = raw_event.get("user_id", "unknown-user")
    prompt = raw_event.get("prompt", "").lower()
    
    severity = 10
    matched_rules = []
    
    for pattern, score, rule_name in SUSPICIOUS_PATTERNS:
        if re.search(pattern, prompt):
            severity = max(severity, score)
            matched_rules.append(rule_name)

    return build_base_incident(
        source="prompt-monitor",
        event_type="prompt_injection_attempt",
        actor=user_id,
        raw_payload={
            "prompt_snippet": prompt[:200],
            "matched_rules": matched_rules
        },
        severity=severity
    )
