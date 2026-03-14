"""
Sentinel Orchestrator Agent — The central brain of the SOC.
Coordinatess specialized agents, invokes external tools, and maintains reasoning logs.
"""
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from api.schemas import SentinelIncident, SupervisorDecision
from app.tools import threat_intel, domain_analysis, wallet_analysis

def decide_strategy(incident: SentinelIncident) -> SupervisorDecision:
    """
    Orchestrates the investigation and response lifecycle.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    structured_llm = llm.with_structured_output(SupervisorDecision)

    severity = incident.severity or 50
    
    system_message = """
    You are the Sentinel Orchestrator Agent, the lead AI architect for an Autonomous Security Operations Center (SOC).
    Your goal is to coordinate specialized investigative agents and remediation tools.

    INCIDENT CONTEXT:
    - Source: {source}
    - Type: {event_type}
    - Actor: {actor}
    - Severity: {severity}
    - Payload: {payload}

    AVAILABLE ACTIONS:
    - `investigate`: Forensics & tool invocation.
    - `generate_evidence`: Cryptographic hashing.
    - `publish_attestation`: On-chain proof.
    - `generate_report`: Final synthesis.

    AVAILABLE ENRICHMENT TOOLS:
    - `IP_Reputation`: If payload contains an IP.
    - `Domain_Lookup`: If payload contains a URL/Domain.
    - `Wallet_Analyzer`: If actor is a crypto address.

    STRATEGY:
    - Determine priority (CRITICAL/HIGH/MEDIUM/LOW).
    - Select actions and tools.
    - Provide deep reasoning for your strategy.
    """

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_message),
        ("user", "Design the investigation and response orchestration for this incident.")
    ])

    chain = prompt | structured_llm
    decision = chain.invoke({
        "source": incident.source,
        "event_type": incident.event_type,
        "actor": incident.actor,
        "severity": severity,
        "payload": str(incident.raw_payload)
    })
    return decision

def enrich_incident(incident: SentinelIncident, tools: list) -> dict:
    """
    Synchronously calls selected tools to gather intelligence.
    Returns an enrichment dictionary.
    """
    intel = {"indicators": [], "external_data": {}, "threat_score": 0}
    
    # Simple extraction logic from payload
    payload_str = str(incident.raw_payload)
    
    if "IP_Reputation" in tools:
        # Dummy extraction for demo
        intel["external_data"]["ip"] = threat_intel.get_ip_reputation("185.220.101.12")
        intel["indicators"].append("IP_REPUTATION_CHECKED")
        
    if "Domain_Lookup" in tools:
        intel["external_data"]["domain"] = domain_analysis.analyze_domain("malicious-c2.com")
        intel["indicators"].append("DOMAIN_ANALYZED")
        
    if "Wallet_Analyzer" in tools:
        intel["external_data"]["wallet"] = wallet_analysis.analyze_wallet(incident.actor)
        intel["indicators"].append("WALLET_RISK_ASSESSED")
        
    return intel
