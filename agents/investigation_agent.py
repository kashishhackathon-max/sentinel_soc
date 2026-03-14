import os
import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage
from api.schemas import IncidentDetection, InvestigationResult
from agents.tools import get_all_tools

def run_investigation(detection_result: IncidentDetection) -> InvestigationResult:
    """
    Takes the structured IncidentDetection object and autonomously investigates 
    its extracted entities using LangChain tool-calling.
    Manual loop ensures compatibility across volatile LangChain versions.
    """
    
    # 1. Initialize LLM and Bind Tools
    llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
    tools = get_all_tools()
    llm_with_tools = llm.bind_tools(tools)
    
    # 2. Prepare the investigation query
    investigation_query = f"""
    The Detection Agent has flagged the following incident:
    Incident ID: {detection_result.incident_id}
    Rule Violated: {detection_result.rule_triggered}
    
    Suspicious Entities extracted:
    {[e.model_dump() for e in detection_result.suspicious_entities]}
    
    Use your tools to investigate these specific entities (check their IPs, wallets, APIs).
    Gather all facts. Form a final decision on the threat level.
    """
    
    messages = [HumanMessage(content=investigation_query)]
    
    # 3. First pass: Agent decides which tools to call
    print(f"Investigating entities for Incident {detection_result.incident_id}...")
    ai_msg = llm_with_tools.invoke(messages)
    messages.append(ai_msg)
    
    # 4. Execute tool calls and feed results back to the messages list
    for tool_call in ai_msg.tool_calls:
        # Find the matching tool function
        selected_tool = next((t for t in tools if t.name == tool_call["name"]), None)
        if selected_tool:
            print(f"Calling tool: {tool_call['name']}({tool_call['args']})")
            tool_output = selected_tool.invoke(tool_call["args"])
            messages.append(ToolMessage(tool_output, tool_call_id=tool_call["id"]))
            
    # 5. Final pass: Get the structured summary from the LLM
    structured_llm = llm.with_structured_output(InvestigationResult)
    final_result = structured_llm.invoke(messages)
    
    return final_result
