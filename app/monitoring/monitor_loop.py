"""
Sentinel Continuous Monitoring Loop
Polls system logs and activity to automatically trigger the security pipeline.
"""
import time
import requests
import random

API_URL = "http://localhost:8000/ingest-event"

def generate_random_incident():
    types = ["unauthorized_access", "wallet_transfer", "anomalous_api_call"]
    actors = ["agent-alpha", "agent-beta", "0xAttackerAddress", "malicious-user-42"]
    
    return {
        "source": "continuous_monitor",
        "event_type": random.choice(types),
        "actor": random.choice(actors),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": random.randint(10, 95),
        "raw_payload": {"activity": "Spontaneous anomalous behavior detected during routine scan."}
    }

def start_monitor():
    print("🛰️ Sentinel Continuous Monitoring Service STARTED.")
    
    # Inject one immediately for the "wow" effect on start
    try:
        requests.post(API_URL, json=generate_random_incident(), timeout=5)
    except: pass

    while True:
        if random.random() > 0.6:  # 40% chance every tick
            incident = generate_random_incident()
            print(f"📡 [Monitor] Detected potential threat: {incident['event_type']}")
            try:
                requests.post(API_URL, json=incident, timeout=5)
            except:
                print("❌ [Monitor] API unreachable. Retrying...")
        
        time.sleep(8)  # Check every 8 seconds for a lively demo

if __name__ == "__main__":
    start_monitor()
