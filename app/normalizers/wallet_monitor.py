"""
Normalizer for Blockchain/Wallet risk events.
"""
from datetime import datetime, timezone

def normalize_wallet_event(raw_data: dict) -> dict:
    """
    Accepts: {"wallet_id": str, "action": str, "target": str, "value": str (optional)}
    Returns: Sentinel Event Schema
    """
    wallet_id = raw_data.get("wallet_id", "unknown-wallet")
    action = raw_data.get("action", "unknown-action")
    target = raw_data.get("target", "unknown-target")
    
    severity = 20
    risk_level = "low"
    
    if action == "unauthorized_sign_request":
        severity = 90
        risk_level = "critical"
    elif action == "contract_interaction" and target.startswith("0x666"): # mock malicious address
        severity = 80
        risk_level = "high"
    elif "obfuscated" in action:
        severity = 70
        risk_level = "medium"

    return {
        "source": "wallet-monitor",
        "event_type": f"wallet_risk:{action}",
        "actor": wallet_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "raw_payload": {
            "action": action,
            "target": target,
            "risk_level": risk_level,
            "metadata": raw_data.get("metadata", {})
        }
    }
