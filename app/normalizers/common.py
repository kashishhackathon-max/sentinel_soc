"""
Shared normalization helpers for Sentinel incidents.
"""
import uuid
from datetime import datetime, timezone
from api.schemas import SentinelIncident
from api import store

def generate_incident_id() -> str:
    return str(uuid.uuid4())[:8]

def map_severity_to_risk(severity: int) -> str:
    if severity >= 80:
        return "Critical"
    if severity >= 60:
        return "High"
    if severity >= 30:
        return "Medium"
    return "Low"

def build_base_incident(
    source: str, 
    event_type: str, 
    actor: str, 
    raw_payload: dict, 
    severity: int = 10,
    incident_id: str = None,
    run_id: str = None
) -> SentinelIncident:
    """Standardizes the creation of a SentinelIncident object."""
    if not incident_id:
        incident_id = generate_incident_id()
    
    if not run_id:
        run_id = store.get_run_id()
        
    return SentinelIncident(
        incident_id=incident_id,
        run_id=run_id,
        source=source,
        event_type=event_type,
        actor=actor,
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity=severity,
        risk_level=map_severity_to_risk(severity),
        raw_payload=raw_payload,
        status="pending"
    )
