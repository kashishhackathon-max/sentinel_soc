"""
Normalizer for AI Agent runtime/tool-call data.
"""
from app.normalizers.common import build_base_incident
from api.schemas import SentinelIncident

def normalize_agent_runtime_event(raw_data: dict) -> SentinelIncident:
    """
    Accepts: {"agent_id": str, "tool": str, "target": str, "args": dict (optional)}
    """
    agent_id = raw_data.get("agent_id", "unknown-agent")
    tool = raw_data.get("tool", "unknown-tool")
    target = raw_data.get("target", "unknown-target")
    
    severity = 10
    if tool == "external_http": severity = 60
    elif tool == "file_system" and "/etc/" in target: severity = 85
    elif "customer_records" in tool: severity = 75

    return build_base_incident(
        source="agent-runtime",
        event_type=f"tool_call:{tool}",
        actor=agent_id,
        raw_payload={
            "tool": tool,
            "target": target,
            "args": raw_data.get("args", {})
        },
        severity=severity
    )
