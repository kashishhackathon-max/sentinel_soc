from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class SuspiciousEntity(BaseModel):
    entity_type: str = Field(description="Type of entity (e.g., 'IP', 'Wallet', 'API_Key')")
    value: str = Field(description="The actual IP address, wallet address, etc.")
    reason: str = Field(description="Why this entity was flagged as suspicious.")


class IncidentDetection(BaseModel):
    incident_id: str = Field(description="Unique identifier for the incident.")
    agent_id: str = Field(description="The ID of the autonomous agent that acted suspiciously.")
    event_timestamp: str = Field(description="When the event occurred.")
    rule_triggered: str = Field(description="The security rule that was violated.")
    suspicious_entities: List[SuspiciousEntity] = Field(description="List of extracted suspicious entities.")
    confidence_score: int = Field(description="Confidence in detection (1-100).", ge=1, le=100)
    severity: int = Field(description="Severity of the violation (1-100).", ge=1, le=100)


class InvestigationResult(BaseModel):
    investigation_summary: str = Field(description="Detailed summary of the investigation findings.")
    threat_score: int = Field(description="Overall threat score after investigation (1-100).", ge=1, le=100)
    evidence_sources: List[str] = Field(description="Sources used to gather evidence (e.g., 'IP Reputation API', 'Wallet Analyzer').")
    risk_level: str = Field(description="Categorical risk level: 'Low', 'Medium', 'High', 'Critical'.")


class EvidenceObject(BaseModel):
    incident_hash: str = Field(description="Keccak256 hash of the full incident report.")
    evidence_location: str = Field(description="Off-chain storage location of the evidence.")
    integrity_hash: str = Field(description="Hash ensuring the evidence hasn't been tampered with.")


class AttestationResult(BaseModel):
    transaction_hash: str = Field(description="Blockchain transaction hash of the attestation.")
    contract_address: str = Field(description="Smart contract where it was recorded.")
    status: str = Field(description="'Success', 'Failed', or 'Mock'.")
    attestation_mode: str = Field(
        default="MOCK",
        description="'REAL' if an on-chain tx was submitted, 'MOCK' if blockchain env is not configured."
    )


class SupervisorDecision(BaseModel):
    priority: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW.")
    actions: List[str] = Field(description="Ordered list of agents/tools to invoke.")
    tools: List[str] = Field(description="Recommended external tools for enrichment.")
    mitigation: List[str] = Field(description="Automated response actions to trigger.")
    reasoning: str = Field(description="Explanation for the chosen strategy.")
    escalation_flag: bool = Field(description="True if human security intervention is required.")
    analyst_recommendations: List[str] = Field(default=[], description="Actionable advice for SOC analysts.")


class IntelligenceEnrichment(BaseModel):
    indicators: List[str] = []
    threat_score: int = 0
    external_data: Dict[str, Any] = {}
    provider: str = "Sentinel-SOC"


class SimulationStartResponse(BaseModel):
    run_id: str
    message: str
    event_count: int


class IncidentReportResponse(BaseModel):
    incident_id: str
    report: Optional[str] = None
    error: Optional[str] = None


class IngestedEvent(BaseModel):
    source: str = Field(description="System or agent source of the event.")
    event_type: str = Field(description="Type of security event.")
    actor: str = Field(description="The entity (agent, user, etc.) performing the action.")
    timestamp: str = Field(description="ISO8601 timestamp of the event.")
    severity: int = Field(description="Initial severity score (1-100).", ge=1, le=100)
    raw_payload: dict = Field(description="Additional technical metadata for investigation.")


class SentinelIncident(BaseModel):
    incident_id: str
    run_id: Optional[str] = None
    source: str
    event_type: str
    actor: str
    timestamp: str  # ISO8601
    severity: Optional[int] = None
    risk_level: Optional[str] = None
    raw_payload: dict
    status: str = "pending"
    
    # Supervisor/Orchestrator additions
    priority: str = "MEDIUM"
    orchestrator_decision: Optional[SupervisorDecision] = None
    
    # Explainable Reasoning
    reasoning_trace: Dict[str, str] = {}
    
    # Intelligence Enrichment
    intel: Optional[IntelligenceEnrichment] = None
    
    # Per-Agent Real-Time Status Tracking
    classifier_status: str = "pending"
    investigation_status: str = "pending"
    evidence_status: str = "pending"
    attestation_status: str = "pending"
    report_status: str = "pending"
    
    # Optional extensions
    tags: List[str] = []
    mode: str = "demo"
    report_path: Optional[str] = None
    attestation_mode: str = "PENDING"
    errors: List[str] = []

    # Recommendations & Remediation
    analyst_recommendations: List[str] = []
    remediation_state: str = "none"  # none, suggested, executed, skipped

class RuntimeEvent(BaseModel):
    eventId: str = Field(description="Unique UUID for this event")
    timestamp: str = Field(description="ISO8601 timestamp")
    agentId: str = Field(description="ID of the monitored agent")
    sessionId: Optional[str] = Field(default=None, description="Current session ID")
    source: str = Field(description="Source component (e.g., tool-executor)")
    eventType: str = Field(description="Type: tool_call, file_access, etc.")
    action: str = Field(description="The specific action performed")
    resource: Optional[str] = Field(default=None, description="The resource accessed (file path, URL, etc.)")
    destination: Optional[str] = Field(default=None, description="Target for outbound requests")
    metadata: Dict[str, Any] = Field(default={}, description="Additional technical metadata")
    riskSignals: List[str] = Field(default=[], description="Signals identified during preprocessing")


class LiveIncident(BaseModel):
    id: str = Field(description="Unique incident UUID")
    timestamp: str = Field(description="ISO8601 detection timestamp")
    agentId: str = Field(description="ID of the malicious agent")
    type: str = Field(description="Incident type/category")
    severity: str = Field(description="critical, high, medium, low")
    description: str = Field(description="Human-readable explanation of the threat")
    sourceEventId: str = Field(description="The event ID that triggered this incident")
    status: str = Field(default="open", description="open, resolved, archived")
