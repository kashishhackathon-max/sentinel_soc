"""
Supervisor Verification Script
Demonstrates autonomous decision-making by sending incidents of different severities.
"""

import requests
import time
import uuid

API = "http://localhost:8000"

def send_incident(event_type, actor, severity, payload):
    print(f"\n🚀 Sending {event_type} (Severity: {severity})...")
    data = {
        "source": "manual_test",
        "event_type": event_type,
        "actor": actor,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": severity,
        "raw_payload": payload
    }
    resp = requests.post(f"{API}/ingest-event", json=data)
    if resp.ok:
        result = resp.json()
        print(f"✅ Ingested: {result['incident_id']}")
        return result['incident_id']
    else:
        print(f"❌ Failed: {resp.text}")
        return None

def main():
    print("=== Sentinel Supervisor Autonomous SOC Test ===")
    
    # 1. LOW SEVERITY - Should only generate report
    id_low = send_incident(
        "minor_anomaly", 
        "agent-001", 
        15, 
        {"msg": "Slightly high memory usage"}
    )
    
    # 2. MEDIUM SEVERITY - Should investigate + report
    id_med = send_incident(
        "unauthorized_access_attempt", 
        "agent-002", 
        45, 
        {"target": "/tmp/test", "result": "denied"}
    )
    
    # 3. HIGH SEVERITY - Should investigate + attest + report
    id_high = send_incident(
        "suspicious_outbound_api", 
        "agent-003", 
        82, 
        {"url": "http://malicious-c2.com/exfiltrate", "method": "POST"}
    )
    
    # 4. CRITICAL SEVERITY - Should do everything + Mitigation
    id_crit = send_incident(
        "large_wallet_drain", 
        "0xAttackerAddress", 
        95, 
        {"amount": "500 ETH", "to": "0xMixerAddress"}
    )

    print("\nIncidents queued. Open the dashboard to watch the Supervisor's dynamic strategies:")
    print("http://localhost:8000/dashboard/")

if __name__ == "__main__":
    main()
