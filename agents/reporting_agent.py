import os
from langchain_openai import ChatOpenAI
from api.schemas import IncidentDetection, InvestigationResult, EvidenceObject, AttestationResult

def generate_trust_report(
    detection: IncidentDetection, 
    investigation: Optional[InvestigationResult] = None, 
    evidence: Optional[EvidenceObject] = None, 
    attestation: Optional[AttestationResult] = None,
    reasoning_trace: Dict[str, str] = {},
    analyst_recommendations: List[str] = []
) -> str:
    """
    Takes the structured outputs from all previous agents and generates a human-readable 
    markdown summary to be presented in the dashboard and stored on disk.
    """
    
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    
    prompt = f"""
    You are the Sentinel Reporting Analyst.
    Your job is to take the structured outputs from the detection, investigation, and attestation phases 
    and produce a beautiful, highly professional Markdown 'Incident Trust Report'.
    
    DETECTION PHASE:
    {detection.model_dump_json(indent=2)}
    
    INVESTIGATION PHASE:
    {investigation.model_dump_json(indent=2) if investigation else "SKIPPED"}
    
    EVIDENCE CREATED:
    {evidence.model_dump_json(indent=2) if evidence else "SKIPPED"}
    
    ON-CHAIN RECORDING:
    {attestation.model_dump_json(indent=2) if attestation else "SKIPPED"}
    
    Please output ONLY the markdown report. The report must include sections for:
    - Incident Overview
    - Root Cause Analysis (based on investigation)
    - Entities Investigated
    - Cryptographic Evidence Links (Incident Hash, Integrity Check, TX Hash on Base testnet)
    - Explainable Reasoning Trace (Summarize the reasoning for each agent step)
    - Recommended Analyst Actions (Display the actionable advice from the Supervisor)
    - Trust Score Update (Determine how much the agent's trust score should drop out of 100 based on the severity).
    """
    
    response = llm.invoke(prompt)
    return response.content
