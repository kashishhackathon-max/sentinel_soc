"""
Sentinel Instrumentation Hooks
Use these wrappers in your agent or application to automatically 
report runtime events to the Sentinel SOC.
"""

import requests
import time
import uuid
import os
import functools
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SENTINEL_API = os.getenv("SENTINEL_API_URL", "http://localhost:8000")

def emit_sentinel_event(
    agent_id: str,
    event_type: str,
    action: str,
    source: str = "instrumented-app",
    resource: Optional[str] = None,
    destination: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None
):
    """Sends a real runtime event to the Sentinel ingestion endpoint."""
    payload = {
        "eventId": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agentId": agent_id,
        "sessionId": session_id,
        "source": source,
        "eventType": event_type,
        "action": action,
        "resource": resource,
        "destination": destination,
        "metadata": metadata or {},
        "riskSignals": []
    }
    
    try:
        response = requests.post(f"{SENTINEL_API}/events/ingest", json=payload, timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "incident_detected":
                print(f"⚠️ [Sentinel] SECURITY INCIDENT DETECTED: {data.get('incident_id')}")
        return response
    except Exception as e:
        print(f"❌ [Sentinel] Failed to emit event: {e}")
        return None

# ── Higher-Level Wrappers ───────────────────────────────────────────────────

def monitor_tool_call(agent_id: str):
    """Decorator to monitor agent tool executions."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            emit_sentinel_event(
                agent_id=agent_id,
                event_type="tool_call",
                action=func.__name__,
                metadata={"args": str(args), "kwargs": str(kwargs)}
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator

def track_file_access(agent_id: str, file_path: str, action: str = "read"):
    """Track manual file system interactions."""
    emit_sentinel_event(
        agent_id=agent_id,
        event_type="file_access",
        action=action,
        resource=file_path
    )

def track_http_request(agent_id: str, url: str, method: str = "GET"):
    """Track outbound network activity."""
    emit_sentinel_event(
        agent_id=agent_id,
        event_type="outbound_http",
        action=method,
        destination=url
    )

# ── Example Usage ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing Sentinel Instrumentation...")
    
    # 1. Test benign event
    emit_sentinel_event("agent-007", "tool_call", "get_weather", resource="London")
    
    # 2. Test malicious event (triggers rule engine)
    print("\nTriggering malicious event simulation...")
    track_file_access("agent-007", "/etc/passwd", "read")
    
    # 3. Test outbound HTTP to untrusted domain
    track_http_request("agent-007", "http://malicious-site.com/exfill", "POST")
