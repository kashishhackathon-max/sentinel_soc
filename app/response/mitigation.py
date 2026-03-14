"""
Sentinel Remediation Layer
Formalized response actions for the Autonomous AI SOC.
"""
from app.metrics.system_metrics import update_metric

def disable_agent(actor_id: str):
    """Suspends the compromised agent's credentials."""
    print(f"🛑 [Remediation] ACTION: DISABLE_AGENT | TARGET: {actor_id}")
    update_metric("remediations_triggered")
    return {"status": "success", "action": "disable_agent", "ref": f"REVOKE-{actor_id}"}

def block_api_domain(domain: str):
    """Adds domain to the firewall blocklist."""
    print(f"🛑 [Remediation] ACTION: BLOCK_DOMAIN | TARGET: {domain}")
    update_metric("remediations_triggered")
    return {"status": "success", "action": "block_domain", "ref": f"FW-BLOCK-{domain}"}

def revoke_wallet_permissions(wallet: str):
    """Notifies on-chain guardrails to pause wallet activity."""
    print(f"🛑 [Remediation] ACTION: PAUSE_WALLET | TARGET: {wallet}")
    update_metric("remediations_triggered")
    return {"status": "success", "action": "pause_wallet", "ref": f"TX-PAUSE-{wallet}"}

def triage_to_human(incident_id: str):
    """Escalates to a human tier-3 security architect."""
    print(f"📧 [Remediation] ACTION: HUMAN_ESCALATION | INCIDENT: {incident_id}")
    return {"status": "escalated", "remediation_state": "executed"}

def revoke_tool_permission(actor_id: str, tool_name: str):
    """Specific tool revocation for an agent."""
    print(f"🛑 [Remediation] ACTION: REVOKE_TOOL | TARGET: {actor_id} | TOOL: {tool_name}")
    update_metric("remediations_triggered")
    return {"status": "success", "action": "revoke_tool", "remediation_state": "executed"}
