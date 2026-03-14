"""
Sentinel Incident Store — Thread-safe in-memory runtime state registry.

This is the single source of truth for live agent execution state.
The dashboard reads from this store via the API. No stale file reads.
"""

import threading
from typing import Dict, Optional
from datetime import datetime, timezone

from api.schemas import SentinelIncident

_store: Dict[str, dict] = {}
_lock = threading.Lock()
_current_run_id: Optional[str] = None


def set_run_id(run_id: str) -> None:
    global _current_run_id
    with _lock:
        _current_run_id = run_id


def get_run_id() -> str:
    """Returns the current run_id. If none exists, initializes a persistent 'LIVE-RUN' context."""
    global _current_run_id
    with _lock:
        if _current_run_id is None:
            _current_run_id = f"LIVE-RUN-{datetime.now(timezone.utc).strftime('%Y%j')}"
        return _current_run_id


def clear_store() -> None:
    """Wipe all incidents — called at the start of each new simulation run."""
    with _lock:
        _store.clear()


def create_incident(incident: SentinelIncident) -> dict:
    """Register a new incident in the store from a NormalizedIncident object."""
    record = incident.dict()
    # Add display snippet if not present (backwards compatibility for UI)
    if "event_snippet" not in record:
        # Construct a snippet if it's missing
        record["event_snippet"] = f"[{incident.source}] {incident.event_type} | Actor: {incident.actor}"
        
    with _lock:
        _store[incident.incident_id] = record
    return record


def update_incident(incident_id: str, **kwargs) -> Optional[dict]:
    """Patch any fields on an existing incident record."""
    with _lock:
        if incident_id not in _store:
            return None
        _store[incident_id].update(kwargs)
        return _store[incident_id].copy()


def get_incident(incident_id: str) -> Optional[dict]:
    with _lock:
        return _store.get(incident_id, None)


def get_all_incidents() -> list:
    """Return all incidents for the current run, sorted by timestamp."""
    with _lock:
        return sorted(_store.values(), key=lambda x: x["timestamp"])
