"""
Sentinel Evaluation Framework — reads from the live /incidents API.
Run AFTER completing a simulation: python evaluation/metrics.py
"""

import json
import os
import sys
import time
import requests

API_BASE = os.getenv("SENTINEL_API_URL", "http://localhost:8000")


def wait_for_completion(timeout: int = 300) -> list:
    """Poll /incidents until all incidents are done or timeout is reached."""
    start = time.time()
    print("⏳ Waiting for simulation to complete…")
    while time.time() - start < timeout:
        try:
            resp = requests.get(f"{API_BASE}/incidents", timeout=10)
            resp.raise_for_status()
            incidents = resp.json()
            if not incidents:
                time.sleep(3)
                continue
            done = all(i.get("status") in ("complete", "failed") for i in incidents)
            if done:
                return incidents
        except Exception as e:
            print(f"  [poll error] {e}")
        time.sleep(3)
    print(f"⚠️  Timeout after {timeout}s. Using partial results.")
    return requests.get(f"{API_BASE}/incidents", timeout=10).json()


def evaluate_metrics() -> None:
    """
    Computes and saves detection/attestation metrics from the live /incidents state.
    """
    print("🔬 Sentinel Evaluation Pipeline")
    print(f"   API: {API_BASE}\n")

    start_time = time.time()

    try:
        incidents = wait_for_completion()
    except Exception as e:
        print(f"❌ Cannot reach Sentinel API: {e}")
        print("   Make sure 'python api/main.py' is running.")
        sys.exit(1)

    if not incidents:
        print("❌ No incidents found. Run a simulation first.")
        sys.exit(1)

    end_time = time.time()
    elapsed = end_time - start_time

    total = len(incidents)
    complete = [i for i in incidents if i.get("status") == "complete"]
    failed   = [i for i in incidents if i.get("status") == "failed"]

    # Detection accuracy: High/Critical incidents that the LLM correctly flagged
    high_risk = [i for i in complete if i.get("risk_level") in ("High", "Critical")]
    # expected: 3 malicious + 4 suspicious = 7
    EXPECTED_ANOMALIES = 7
    EXPECTED_NORMAL    = 3

    # False positives: Low-risk incidents where severity > 20 (LLM over-flagged a normal event)
    false_positives = [
        i for i in complete
        if (i.get("risk_level") in ("Low",) and (i.get("severity") or 0) > 20)
    ]

    detection_accuracy = min((len(high_risk) / EXPECTED_ANOMALIES) * 100, 100) if EXPECTED_ANOMALIES else 0
    fp_rate = (len(false_positives) / EXPECTED_NORMAL) * 100 if EXPECTED_NORMAL else 0
    avg_time = elapsed / total if total else 0

    real_attestations = [i for i in complete if i.get("attestation_mode") == "REAL"]
    mock_attestations = [i for i in complete if i.get("attestation_mode") == "MOCK"]

    severities = [i["severity"] for i in complete if i.get("severity")]
    avg_severity = round(sum(severities) / len(severities), 1) if severities else 0

    run_id = incidents[0].get("run_id", "unknown") if incidents else "unknown"

    metrics = {
        "run_id": run_id,
        "evaluation_count": total,
        "complete": len(complete),
        "failed": len(failed),
        "detection_accuracy": f"{detection_accuracy:.1f}%",
        "false_positive_rate": f"{fp_rate:.1f}%",
        "high_risk_detected": len(high_risk),
        "avg_severity_score": avg_severity,
        "real_attestations": len(real_attestations),
        "mock_attestations": len(mock_attestations),
        "attestation_mode": "REAL" if real_attestations else "MOCK",
        "avg_time_per_incident_sec": f"{avg_time:.1f}",
        "network": "Base Sepolia",
    }

    os.makedirs("evaluation", exist_ok=True)
    out_path = os.path.join("evaluation", "metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"✅ Evaluation complete. Results saved to {out_path}\n")
    print(json.dumps(metrics, indent=4))


if __name__ == "__main__":
    evaluate_metrics()
