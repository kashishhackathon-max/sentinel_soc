"""
Sentinel Rule Engine
Evaluates real-time events against security policies to detect malicious intent.
"""

from typing import List, Optional, Tuple
from api.schemas import RuntimeEvent, LiveIncident
import uuid
from datetime import datetime, timezone

# Security Policies
SENSITIVE_FILES = [".env", "id_rsa", "/etc/passwd", "wallet.json", "key.pem", "secrets.json"]
DANGEROUS_COMMANDS = ["rm -rf", "chmod", "curl", "wget", "nc", "nmap"]
UNTRUSTED_DOMAINS = ["malicious-site.com", "hacker-c2.net"]

def evaluate_event(event: RuntimeEvent) -> Optional[LiveIncident]:
    """
    Analyzes a single RuntimeEvent and returns a LiveIncident if a rule is triggered.
    """
    detections = []
    severity = "low"
    incident_type = "suspicious_activity"
    
    # 1. Sensitive File Access
    if event.eventType == "file_access" or event.eventType == "tool_call":
        resource = (event.resource or "").lower()
        if any(f in resource for f in SENSITIVE_FILES):
            detections.append(f"Unauthorized access attempt to sensitive file: {resource}")
            severity = "critical"
            incident_type = "data_exfiltration_attempt"

    # 2. Subprocess Execution / Dangerous Commands
    if event.eventType == "subprocess_exec" or event.eventType == "tool_call":
        action = (event.action or "").lower()
        if any(cmd in action for cmd in DANGEROUS_COMMANDS):
            detections.append(f"Execution of dangerous or restricted command: {action}")
            severity = "critical"
            incident_type = "unauthorized_shell_execution"

    # 3. Outbound HTTP to Untrusted Domains
    if event.eventType == "outbound_http":
        dest = (event.destination or "").lower()
        if any(dom in dest for f in UNTRUSTED_DOMAINS):
            detections.append(f"Outbound connection to suspected C2 domain: {dest}")
            severity = "critical"
            incident_type = "c2_communication_detected"

    # 4. Policy Violation Signals
    if "policy_violation" in event.eventType or "override" in (event.action or "").lower():
        detections.append(f"Agent attempted to override system security policy: {event.action}")
        severity = "high"
        incident_type = "policy_bypass_attempt"

    # 5. Risk Score Evaluation (if provided in metadata)
    risk_score = event.metadata.get("riskScore", 0)
    if risk_score > 0.7:
        detections.append(f"High risk score ({risk_score}) identified by pre-processor.")
        if severity != "critical":
            severity = "high"

    if detections:
        return LiveIncident(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agentId=event.agentId,
            type=incident_type,
            severity=severity,
            description=" | ".join(detections),
            sourceEventId=event.eventId,
            status="open"
        )
    
    return None
