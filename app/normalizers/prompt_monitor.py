"""
Normalizer for AI Agent prompt monitoring.
Detects suspicious instructions or data exfiltration attempts in prompt text.
"""
from datetime import datetime, timezone
import re

SUSPICIOUS_PATTERNS = [
    (r"ignore previous instructions", 90, "instruction_override"),
    (r"reveal (secrets|api key|credentials)", 85, "data_exfiltration"),
    (r"exfiltrate", 80, "data_exfiltration"),
    (r"system prompt", 70, "policy_bypass"),
    (r"delete archives", 95, "destructive_action")
]

def normalize_prompt_event(raw_data: dict) -> dict:
    """
    Accepts: {"user_id": str, "prompt": str}
    Returns: Sentinel Event Schema
    """
    user_id = raw_data.get("user_id", "unknown-user")
    prompt = raw_data.get("prompt", "").lower()
    
    max_severity = 10
    matched_rules = []
    
    for pattern, severity, rule_name in SUSPICIOUS_PATTERNS:
        if re.search(pattern, prompt):
            max_severity = max(max_severity, severity)
            matched_rules.append(rule_name)

    return {
        "source": "prompt-monitor",
        "event_type": "prompt_injection_attempt",
        "actor": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": max_severity,
        "raw_payload": {
            "prompt_snippet": prompt[:200],
            "matched_rules": matched_rules,
            "risk_score": max_severity
        }
    }
