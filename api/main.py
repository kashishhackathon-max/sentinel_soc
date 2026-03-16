"""
Sentinel API — Live Execution Orchestrator
FastAPI backend driving the 5-agent pipeline with real-time state tracking.
"""

import sys
import os
import uuid
import shutil
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

import queue
import threading
import time
from typing import List, Optional, Dict, Any
from api import store
from api.schemas import SimulationStartResponse, IncidentReportResponse, IngestedEvent, SupervisorDecision, RuntimeEvent
from app.monitoring.continuous_monitor import ContinuousMonitor
from app.monitoring.rules import evaluate_event
import uuid

# ── Sentinel Agents ─────────────────────────────────────────────────────────
from agents.detection_agent import run_detection
from agents.investigation_agent import run_investigation
from agents.evidence_agent import generate_evidence
from agents.attestation_agent import publish_attestation
from agents.reporting_agent import generate_trust_report
from agents.supervisor_agent import decide_strategy as run_supervisor
from app.queue.priority_queue import IncidentPriorityQueue
from app.response import mitigation
from app.metrics import system_metrics

# ── Normalizers ──────────────────────────────────────────────────────────────
from app.normalizers.agent_runtime import normalize_agent_runtime_event
from app.normalizers.prompt_events import normalize_prompt_event
from app.normalizers.wallet_events import normalize_wallet_event
from app.normalizers.common import build_base_incident
from api.schemas import SentinelIncident

load_dotenv()

# ── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="Sentinel Live Trust Orchestrator", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Priority Queue System ─────────────────────────────────────────────────────
INCIDENT_QUEUE = IncidentPriorityQueue()

def pipeline_worker():
    """Background thread that pulls from the priority queue and runs the pipeline."""
    while True:
        try:
            task_data = INCIDENT_QUEUE.get(timeout=5)
            incident_id, run_id, event_data = task_data
            process_incident_autonomously(incident_id, run_id, event_data)
            INCIDENT_QUEUE.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[Worker ❌] Critical error in pipeline worker: {e}")
            time.sleep(5)

# Start worker thread
worker_thread = threading.Thread(target=pipeline_worker, daemon=True)
worker_thread.start()

# ── Monitoring System ────────────────────────────────────────────────────────
MONITOR = ContinuousMonitor()
monitor_thread = None

def monitoring_task():
    MONITOR.start()

# ── Sentinel Mode ────────────────────────────────────────────────────────────
SENTINEL_MODE = os.getenv("SENTINEL_MODE", "demo").lower()
if SENTINEL_MODE == "demo":
    from simulation.demo_events import SIMULATION_EVENTS
else:
    SIMULATION_EVENTS = []


# ── Archive Helpers ──────────────────────────────────────────────────────────
def archive_stale_reports(run_id: str) -> None:
    """Move any existing reports to an archive folder so only current-run reports exist."""
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    archive_dir = os.path.join(reports_dir, "archive", run_id)
    os.makedirs(reports_dir, exist_ok=True)

    stale_files = [
        f for f in os.listdir(reports_dir)
        if f.endswith(".md") and os.path.isfile(os.path.join(reports_dir, f))
    ]
    if stale_files:
        os.makedirs(archive_dir, exist_ok=True)
        for fname in stale_files:
            shutil.move(os.path.join(reports_dir, fname), os.path.join(archive_dir, fname))
        print(f"[Store] Archived {len(stale_files)} stale report(s) to reports/archive/{run_id}/")


# ── Background Pipeline Task ─────────────────────────────────────────────────
def process_incident_autonomously(incident_id: str, run_id: str, event_data: str) -> None:
    """
    Autonomous pipeline orchestrated by the Supervisor Agent.
    """
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    def push(status: Optional[str] = None, **kwargs):
        if status:
            store.update_incident(incident_id, status=status, **kwargs)
        else:
            store.update_incident(incident_id, **kwargs)

    try:
        raw_incident_dict = store.get_incident(incident_id)
        if not raw_incident_dict: return
        incident_obj = SentinelIncident(**raw_incident_dict)

        # ── Phase 0: Supervisor Decision ──────────────────────────────────
        push("orchestrator_running")
        system_metrics.update_metric("total_incidents")
        
        # Determine attestation mode early
        private_key = os.getenv("DEPLOYER_PRIVATE_KEY", "")
        is_live = private_key and private_key != "your_metamask_private_key_here"
        att_mode = "REAL" if is_live else "MOCK"

        decision = run_supervisor(incident_obj)
        reasoning = {"supervisor": decision.reasoning}
        
        push(
            "orchestrator_complete",
            priority=decision.priority,
            orchestrator_decision=decision.dict(),
            reasoning_trace=reasoning,
            analyst_recommendations=decision.analyst_recommendations,
            remediation_state="suggested" if decision.mitigation else "none",
            attestation_mode=att_mode
        )
        print(f"[Supervisor 🧠] Strategy for {incident_id}: {decision.actions} | Priority: {decision.priority}")

        # ── Phase 1: Dynamic Execution & Enrichment ─────────────────────────
        detection = None
        investigation = None
        evidence = None
        attestation = None

        # Always run detection
        push("detection_running", classifier_status="running")
        detection = run_detection(event_data)
        reasoning["detection"] = "Extracted security indicators from raw system logs."
        
        push(
            "detection_complete",
            classifier_status="complete",
            severity=detection.severity,
            agent_id=detection.agent_id,
            rule_triggered=detection.rule_triggered,
            confidence_score=detection.confidence_score,
            reasoning_trace=reasoning
        )
        if detection.severity >= 90:
            system_metrics.update_metric("critical_threats")

        # ── Phase 2: Autonomous Remediation ──────────────────────────────────
        for action in decision.mitigation:
            if action == "disable_agent":
                mitigation.disable_agent(incident_obj.actor)
            elif action == "block_domain":
                mitigation.block_api_domain("external-malicious-target.com")
            elif action == "pause_wallet":
                mitigation.revoke_wallet_permissions(incident_obj.actor)
            elif action == "notify_security":
                mitigation.triage_to_human(incident_id)

        # ── Phase 3: Investigation ──────────────────────────────────────────
        if "investigate" in decision.actions:
            push("investigation_running", investigation_status="running")
            investigation = run_investigation(detection)
            reasoning["investigation"] = "Cross-referenced indicators with external threat intelligence APIs."
            push("investigation_complete", investigation_status="complete", risk_level=investigation.risk_level, reasoning_trace=reasoning)
        else:
            push(investigation_status="skipped")

        if "generate_evidence" in decision.actions:
            push("evidence_running", evidence_status="running")
            evidence = generate_evidence(detection, investigation)
            reasoning["evidence"] = "Generated Keccak256 proof of incident integrity."
            push("evidence_complete", evidence_status="complete", reasoning_trace=reasoning)
        else:
            push(evidence_status="skipped")

        if "publish_attestation" in decision.actions:
            push("attestation_running", attestation_status="running")
            attestation = publish_attestation(detection, evidence)
            if attestation.status == "Success":
                system_metrics.update_metric("attestations_success")
            
            reasoning["attestation"] = f"Submitted cryptographic proof to Base Sepolia. Mode: {att_mode}"
            push(
                "attestation_complete",
                attestation_status="complete",
                attestation_mode=att_mode,
                transaction_hash=attestation.transaction_hash,
                contract_address=attestation.contract_address,
                reasoning_trace=reasoning
            )
        else:
            push(attestation_status="skipped", attestation_mode=att_mode)

        # ── Phase 5: Reporting ──────────────────────────────────────────────
        push("report_running", report_status="running")
        markdown_report = generate_trust_report(
            detection, 
            investigation, 
            evidence, 
            attestation,
            reasoning_trace=reasoning,
            analyst_recommendations=decision.analyst_recommendations
        )

        if SENTINEL_MODE == "demo":
            markdown_report = f"## 🧪 DEMO INCIDENT\n\n{markdown_report}"

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_filename = f"{incident_id}_{ts}.md"
        report_path = os.path.join(reports_dir, report_filename)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(markdown_report)

        push(
            "complete",
            report_status="complete",
            report_path=report_path,
        )
        print(f"[Pipeline ✅] Incident {incident_id} complete. Strategy followed.")

    except Exception as e:
        err_msg = str(e)
        print(f"[Pipeline ❌] Incident {incident_id} FAILED: {err_msg}")
        store.update_incident(incident_id, status="failed", errors=[err_msg])

def run_pipeline(incident_id: str, run_id: str, event_data: str) -> None:
    """Queues the incident. Now initially handled by the Supervisor in the worker."""
    INCIDENT_QUEUE.put("MEDIUM", incident_id, run_id, event_data)
    print(f"[Queue ⏳] Incident {incident_id} queued for triage.")


@app.get("/metrics")
def get_system_metrics():
    """Returns real-time performance and threat indicators."""
    if store.get_monitoring_status():
        return store.get_live_metrics()
    return system_metrics.get_metrics()


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
async def root_redirect():
    """Redirect root access to the dashboard."""
    return RedirectResponse(url="/dashboard")

@app.get("/health")
def health():
    """System health check — lets the dashboard know what attestation mode we're in."""
    private_key = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    contract_address = os.getenv("CONTRACT_ADDRESS", "")
    is_live = (
        private_key and private_key != "your_metamask_private_key_here"
        and contract_address and contract_address != "0x_deployed_contract_address_here"
    )
    all_incidents = store.get_all_incidents()
    return {
        "status": "ok",
        "mode": SENTINEL_MODE.upper(),
        "active_incidents": len(all_incidents),
        "current_run_id": store.get_run_id(),
        "attestation_mode": "LIVE_ATTESTATION" if is_live else "MOCK_ATTESTATION",
    }


@app.post("/demo/simulation/start", response_model=SimulationStartResponse)
def simulation_start(background_tasks: BackgroundTasks):
    """
    Triggers a fresh 10-event simulation run.
    Only enabled in SENTINEL_MODE=demo.
    """
    if SENTINEL_MODE != "demo":
        raise HTTPException(status_code=403, detail="Simulation disabled in live mode.")
    run_id = str(uuid.uuid4())
    store.set_run_id(run_id)
    store.clear_store()
    system_metrics.update_metric("total_incidents", -system_metrics.get_metrics()["total_incidents"])
    system_metrics.update_metric("critical_threats", -system_metrics.get_metrics()["critical_threats"])
    system_metrics.update_metric("attestations_success", -system_metrics.get_metrics()["attestations_success"])
    system_metrics.update_metric("remediations_triggered", -system_metrics.get_metrics()["remediations_triggered"])
    archive_stale_reports(run_id)

    for event_data in SIMULATION_EVENTS:
        incident = build_base_incident(
            source="simulation",
            event_type="DEMO_EVENT",
            actor="simulator",
            raw_payload={"content": event_data},
            severity=50,
            run_id=run_id
        )
        incident.mode = "demo"
        store.create_incident(incident)
        background_tasks.add_task(run_pipeline, incident.incident_id, run_id, event_data)

    return SimulationStartResponse(
        run_id=run_id,
        message=f"Demo Simulation started. {len(SIMULATION_EVENTS)} events queued.",
        event_count=len(SIMULATION_EVENTS),
    )



# ── Live Monitoring Controls ────────────────────────────────────────────────
@app.post("/monitor/start")
def start_live_monitoring():
    """Enable real runtime ingestion and rule detection."""
    store.set_monitoring_status(True)
    print("🛰️ [Sentinel] Live monitoring ENABLED. Ready for ingestion.")
    return {"status": "monitoring_started", "mode": "LIVE"}


@app.post("/monitor/stop")
def stop_live_monitoring():
    """Disable runtime monitoring."""
    store.set_monitoring_status(False)
    print("🛑 [Sentinel] Live monitoring DISABLED.")
    return {"status": "monitoring_stopped"}


@app.get("/status")
def get_monitoring_status():
    """Report whether monitoring is active and what's connected."""
    return {
        "monitoring_active": store.get_monitoring_status(),
        "live_events_processed": store.get_live_metrics()["eventsProcessed"],
        "connected_sources": ["agent-runtime", "prompt-monitor", "wallet-monitor"]
    }


@app.post("/events/ingest")
async def ingest_runtime_event(event: RuntimeEvent):
    """
    Primary intake for REAL application/agent events.
    Rules are evaluated on every ingestion.
    """
    if not store.get_monitoring_status():
        # Optional: accept but don't process if monitoring is OFF, 
        # or return an error/warning.
        return {"status": "ignored", "reason": "Monitoring is disabled"}

    # 1. Update global event count
    store.increment_live_events()

    # 2. Run rule engine evaluation
    incident = evaluate_event(event)

    if incident:
        # 3. If a rule triggered, add to live incident list
        store.add_live_incident(incident.dict())
        print(f"🚨 [Detection] INCIDENT CREATED: {incident.type} for agent {event.agentId}")
        return {"status": "incident_detected", "incident_id": incident.id}

    return {"status": "processed", "incident_detected": False}


@app.post("/simulate-attack")
async def simulate_attack():
    """
    Developer tool to verify detection by injecting a malicious event.
    """
    attack_event = RuntimeEvent(
        eventId=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agentId="testing-attacker-01",
        source="manual-simulation",
        eventType="tool_call",
        action="read_sensitive_file",
        resource="/etc/passwd",
        metadata={"riskScore": 0.95}
    )
    
    # We use the same ingestion logic to prove the detection engine works
    return await ingest_runtime_event(attack_event)


@app.get("/incidents")
def list_incidents():
    """Real-time list of all incidents in the current run."""
    if store.get_monitoring_status():
        return store.get_live_incidents()
    return store.get_all_incidents()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Single incident runtime state."""
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found in current run.")
    return incident


@app.get("/incidents/{incident_id}/report", response_model=IncidentReportResponse)
def get_incident_report(incident_id: str):
    """
    Return the actual markdown content generated by the Reporting Agent for this incident.
    Returns an error if the report is not yet generated (pipeline still running).
    Crucially, the report is only served if it belongs to the CURRENT run.
    """
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found in current run.")

    report_path = incident.get("report_path")
    if not report_path or not os.path.exists(report_path):
        return IncidentReportResponse(
            incident_id=incident_id,
            error="Report not yet generated. Pipeline is still running.",
        )

    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()

    return IncidentReportResponse(incident_id=incident_id, report=content)


# ── Legacy endpoint for backward compatibility ────────────────────────────────
class EventLog(BaseModel):
    event_data: str

@app.post("/analyze")
def analyze_single_event(log: EventLog, background_tasks: BackgroundTasks):
    """
    Single-event analysis. Creates an isolated incident not tied to a simulation run.
    Useful for manual testing of individual events.
    """
    run_id = store.get_run_id() or "manual"
    incident_id = str(uuid.uuid4())[:8]
    store.create_incident(incident_id, run_id, log.event_data, mode=SENTINEL_MODE)
    background_tasks.add_task(run_pipeline, incident_id, run_id, log.event_data)
    return {"status": "queued", "incident_id": incident_id, "run_id": run_id}


@app.post("/ingest-event")
async def ingest_event(event: IngestedEvent, background_tasks: BackgroundTasks):
    """
    Production ingestion endpoint. 
    Accepts a structured event, normalizes it for the agents, and triggers the pipeline.
    """
    run_id = store.get_run_id()
    incident_id = str(uuid.uuid4())[:8]
    
    # Normalize: Convert structured data into a descriptive string for the LLM agents
    # This ensures the agents get the full context in a format they already understand.
    normalization = (
        f"[{event.event_type.upper()}] Source: {event.source} | Actor: {event.actor} | "
        f"Initial Severity: {event.severity} | Payload: {event.raw_payload}"
    )
    
    incident = build_base_incident(
        source=event.source,
        event_type=event.event_type,
        actor=event.actor,
        raw_payload=event.raw_payload,
        severity=event.severity,
        run_id=run_id
    )
    
    store.create_incident(incident)
    background_tasks.add_task(run_pipeline, incident.incident_id, run_id, normalization)
    
    return {
        "status": "ingested",
        "incident_id": incident.incident_id,
        "run_id": run_id,
        "processing": True
    }


# ── Source-Specific Ingestion ────────────────────────────────────────────────
@app.post("/ingest/agent-tool-call")
async def ingest_agent_tool_call(raw_data: dict, background_tasks: BackgroundTasks):
    incident = normalize_agent_runtime_event(raw_data)
    store.create_incident(incident)
    
    # Format a string for the legacy pipeline agents
    event_data = f"[{incident.source}] {incident.event_type} | Actor: {incident.actor} | Payload: {incident.raw_payload}"
    background_tasks.add_task(run_pipeline, incident.incident_id, incident.run_id, event_data)
    
    return {"status": "ingested", "incident_id": incident.incident_id, "run_id": incident.run_id}

@app.post("/ingest/prompt-event")
async def ingest_prompt_event(raw_data: dict, background_tasks: BackgroundTasks):
    incident = normalize_prompt_event(raw_data)
    store.create_incident(incident)
    
    event_data = f"[{incident.source}] {incident.event_type} | Actor: {incident.actor} | Prompt: {incident.raw_payload.get('prompt_snippet')}"
    background_tasks.add_task(run_pipeline, incident.incident_id, incident.run_id, event_data)
    
    return {"status": "ingested", "incident_id": incident.incident_id, "run_id": incident.run_id}

@app.post("/ingest/wallet-event")
async def ingest_wallet_event(raw_data: dict, background_tasks: BackgroundTasks):
    incident = normalize_wallet_event(raw_data)
    store.create_incident(incident)
    
    event_data = f"[{incident.source}] {incident.event_type} | Actor: {incident.actor} | Target: {incident.raw_payload.get('target')}"
    background_tasks.add_task(run_pipeline, incident.incident_id, incident.run_id, event_data)
    
    return {"status": "ingested", "incident_id": incident.incident_id, "run_id": incident.run_id}

# ── Static File Serving ──────────────────────────────────────────────────────
_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_dashboard = os.path.join(_base, "dashboard")
_reports = os.path.join(_base, "reports")
_evaluation = os.path.join(_base, "evaluation")

for d in [_dashboard, _reports, _evaluation]:
    os.makedirs(d, exist_ok=True)

app.mount("/dashboard", StaticFiles(directory=_dashboard, html=True), name="dashboard")
app.mount("/evaluation", StaticFiles(directory=_evaluation), name="evaluation")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
