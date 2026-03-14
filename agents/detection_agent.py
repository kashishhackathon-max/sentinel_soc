import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from api.schemas import IncidentDetection
import uuid
from datetime import datetime

def run_detection(event_stream: str) -> IncidentDetection:
    """
    Parses raw agent logs/events and returns a structured Pydantic object identifying the incident.
    """
    
    # Needs to match the model we set in .env or passed globally
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    
    # We enforce structured outputs matching our Pydantic schema exactly.
    structured_llm = llm.with_structured_output(IncidentDetection)
    
    system_prompt = f"""
    You are Sentinel Detection Agent, an expert cybersecurity auditor monitoring autonomous AI agents.
    Analyze the following event logs and extract exactly the suspected malicious or malfunctioning agent behavior.
    
    Focus on:
    - Scope violations (e.g., executing unapproved commands, transferring too much money).
    - Hardcoded or unauthorized IP/Wallet connections.
    - Rate-limit bypassing or API abuse.
    
    Generate a unique `incident_id` like {str(uuid.uuid4())[:8]}.
    Set the `severity` to a value between 1 and 100 based on potential risk.
    Set the `confidence_score` between 1 and 100 representing how likely this is malicious vs a benign mistake.
    If no timestamp is provided, use {datetime.utcnow().isoformat()}.
    
    EVENT LOG STREAM:
    {event_stream}
    """
    
    # Invoke the model to extract
    result = structured_llm.invoke(system_prompt)
    return result
