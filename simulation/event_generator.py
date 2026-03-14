"""
Sentinel Event Simulator — calls POST /simulation/start on the live API.
This triggers all 10 events in a single call.
The API handles queuing them as background tasks.
"""

import requests
import sys
import os
import time
import json

API_BASE = os.getenv("SENTINEL_API_URL", "http://localhost:8000")


def start_simulation() -> dict:
    """Trigger a fresh simulation run via the API."""
    print(f"🚀 Triggering Sentinel Simulation via {API_BASE}/simulation/start ...")
    try:
        response = requests.post(f"{API_BASE}/simulation/start", timeout=15)
        response.raise_for_status()
        data = response.json()
        print(f"✅ Simulation started! Run ID: {data['run_id']}")
        print(f"   {data['event_count']} events queued in the background.\n")
        return data
    except requests.exceptions.ConnectionError:
        print(f"❌ Could not connect to Sentinel API at {API_BASE}.")
        print("   Please start the API first: python api/main.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


def poll_until_complete(run_id: str, poll_interval: float = 3.0) -> list:
    """
    Poll GET /incidents until all 10 incidents have reached 'complete' or 'failed'.
    Prints a live progress table to the terminal.
    """
    print("📡 Polling for live agent results...")
    print(f"{'Incident':<12} {'Status':<25} {'Severity':<10} {'Risk':<12} {'Attestation'}")
    print("─" * 75)

    while True:
        try:
            resp = requests.get(f"{API_BASE}/incidents", timeout=10)
            resp.raise_for_status()
            incidents = resp.json()
        except Exception as e:
            print(f"  [poll error] {e}")
            time.sleep(poll_interval)
            continue

        # Filter to current run
        current = [i for i in incidents if i.get("run_id") == run_id]

        # Render table
        os.system("cls" if os.name == "nt" else "clear")
        print(f"Sentinel Live Simulation  |  Run: {run_id[:8]}...")
        print(f"{'Incident':<12} {'Status':<25} {'Severity':<10} {'Risk':<12} {'Attestation'}")
        print("─" * 75)
        for inc in current:
            severity_str = str(inc.get("severity") or "--")
            risk = inc.get("risk_level") or "--"
            attn = inc.get("attestation_mode", "--")
            status = inc.get("status", "pending")
            print(f"{inc['incident_id']:<12} {status:<25} {severity_str:<10} {risk:<12} {attn}")

        done = all(i.get("status") in ("complete", "failed") for i in current)
        if done and len(current) == 10:
            print("\n✅ All 10 incidents processed.")
            return current

        pending_count = sum(1 for i in current if i.get("status") not in ("complete", "failed"))
        print(f"\n  [{pending_count} still running] — refreshing in {poll_interval}s…")
        time.sleep(poll_interval)


def print_summary(incidents: list) -> None:
    """Print a final summary of the simulation results."""
    print("\n" + "=" * 75)
    print("SENTINEL SIMULATION SUMMARY")
    print("=" * 75)
    complete = [i for i in incidents if i.get("status") == "complete"]
    failed = [i for i in incidents if i.get("status") == "failed"]
    real_chain = [i for i in complete if i.get("attestation_mode") == "REAL"]
    mock_chain = [i for i in complete if i.get("attestation_mode") == "MOCK"]

    print(f"  Total Incidents  : {len(incidents)}")
    print(f"  Completed        : {len(complete)}")
    print(f"  Failed           : {len(failed)}")
    print(f"  On-Chain (REAL)  : {len(real_chain)}")
    print(f"  Mock Attestation : {len(mock_chain)}")
    print()
    for inc in complete:
        tx = inc.get("transaction_hash") or "N/A"
        print(f"  [{inc.get('risk_level','?'):>8}] {inc['incident_id']}  TX: {tx[:30]}...")
    if failed:
        print("\nFailed incidents:")
        for inc in failed:
            print(f"  ❌ {inc['incident_id']}: {inc.get('errors')}")
    print("=" * 75)


if __name__ == "__main__":
    result = start_simulation()
    run_id = result["run_id"]

    print(f"\nDashboard: http://localhost:8000/dashboard/")
    print(f"Live API:  http://localhost:8000/incidents\n")

    incidents = poll_until_complete(run_id)
    print_summary(incidents)
