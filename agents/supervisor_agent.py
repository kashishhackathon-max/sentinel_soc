"""
Sentinel Supervisor Agent
Autonomous orchestrator that triages incidents, determines priority, 
and selects the optimal investigation strategy and tools.
"""
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from api.schemas import SupervisorDecision, SentinelIncident
import os

def decide_strategy(incident: SentinelIncident) -> SupervisorDecision:
    """
    Evaluates a normalized incident and determines priority, agent steps, 
    tools, and analyst recommendations.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    structured_llm = llm.with_structured_output(SupervisorDecision)
    
    system_message = (
        "You are the Sentinel Supervisor Agent, the chief orchestrator of an AI-driven SOC. "
        "Your task is to analyze incoming security events involving autonomous agents and "
        "decide on the urgency and the investigation plan."
    )
    
    user_prompt_template = """
    Analyze this incident and decide on the next steps:
    
    SOURCE: {source}
    EVENT TYPE: {event_type}
    ACTOR: {actor}
    INITIAL SEVERITY: {severity}
    METADATA: {metadata}
    
    GUIDELINES:
    - LOW: Log and summarize. No urgent action.
    - MEDIUM: Investigate, enrich with threat intel, and recommend review.
    - HIGH: Deep investigation, multiple tool lookups, generate report, recommend urgent analyst action.
    - CRITICAL: Immediate escalation, remediation trigger, notify security, full report.
    
    PRIORITY SELECTION:
    - If actor is on a blacklist or severity > 85: CRITICAL.
    - If anomalous API pattern or high-value wallet transfer: HIGH.
    - If suspicious but localized: MEDIUM.
    - If routine warning: LOW.
    
    AVAILABLE AGENTS:
    - detection_agent (always runs)
    - investigation_agent (enrichment/intel)
    - evidence_agent (integrity proof)
    - attestation_agent (blockchain record)
    - reporting_agent (markdown/PDF generation)
    
    AVAILABLE TOOLS:
    - threat_intel (IP/Domain reputation)
    - wallet_analysis (Blockchain forensics)
    - domain_analysis (WHOIS/DGA)
    
    REMEDIATION ACTIONS:
    - disable_agent (Revoke agent credentials)
    - block_domain (Firewall drop)
    - pause_wallet (Stop on-chain activity)
    - notify_security (Email/Slack alert)
    
    OUTPUT: A structured decision including priority, actions, tools, mitigation, 
    reasoning, and specific recommendations for the SOC analyst.
    """
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_message),
        ("human", user_prompt_template)
    ])
    
    chain = prompt | structured_llm
    
    # Safely handle potential serialization issues with metadata
    try:
        metadata_str = str(incident.raw_payload)
    except:
        metadata_str = "Error serializing metadata"

    decision = chain.invoke({
        "source": incident.source,
        "event_type": incident.event_type,
        "actor": incident.actor,
        "severity": incident.severity,
        "metadata": metadata_str
    })
    
    return decision
