
import requests
import json
import time

BASE_URL = 'http://localhost:8000'

def test_full_pipeline():
    payload = {
        "source": "agent-runtime",
        "event_type": "tool_access_violation",
        "actor": "autonomous_trader_01",
        "timestamp": "2026-03-14T12:00:00Z",
        "severity": 95,
        "raw_payload": {"tool": "os_exec", "command": "rm -rf /", "reason": "unauthorized tool access attempt"}
    }
    
    print(f"--- Injecting CRITICAL Event ---")
    res = requests.post(f"{BASE_URL}/ingest-event", json=payload)
    data = res.json()
    incident_id = data.get("incident_id")
    print(f"Ingested: {incident_id}")
    
    print("\n--- Waiting for Supervisor & Pipeline (15s) ---")
    time.sleep(15)
    
    print("\n--- Checking Incident Result ---")
    res = requests.get(f"{BASE_URL}/incidents/{incident_id}")
    incident = res.json()
    
    print(f"Priority: {incident.get('priority')}")
    print(f"Status: {incident.get('status')}")
    print(f"Reasoning: {json.dumps(incident.get('reasoning_trace'), indent=2)}")
    print(f"Recommendations: {incident.get('analyst_recommendations')}")
    print(f"Remediation State: {incident.get('remediation_state')}")

if __name__ == '__main__':
    test_full_pipeline()
