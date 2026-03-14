"""
Normalizer for blockchain/wallet security events.
"""
from app.normalizers.common import build_base_incident
from api.schemas import SentinelIncident

def normalize_wallet_event(raw_event: dict) -> SentinelIncident:
    """
    Accepts: {"wallet_id": str, "action": str, "target": str}
    """
    wallet_id = raw_event.get("wallet_id", "unknown-wallet")
    action = raw_event.get("action", "unknown-action")
    target = raw_event.get("target", "unknown-target")
    
    severity = 20
    if action == "unauthorized_sign_request": severity = 90
    elif action == "contract_interaction" and target.startswith("0x666"): severity = 80

    return build_base_incident(
        source="wallet-monitor",
        event_type=f"wallet_risk:{action}",
        actor=wallet_id,
        raw_payload={
            "action": action,
            "target": target,
            "metadata": raw_event.get("metadata", {})
        },
        severity=severity
    )
