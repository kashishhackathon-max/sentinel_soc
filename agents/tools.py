from langchain_core.tools import tool
import json
from app.tools.threat_intel import get_ip_reputation
from app.tools.domain_analysis import analyze_domain
from app.tools.wallet_analysis import analyze_wallet as run_wallet_analysis

@tool
def check_ip_reputation(ip_address: str) -> str:
    """Checks the reputation of an extracted IP address using threat intelligence sources."""
    result = get_ip_reputation(ip_address)
    return json.dumps(result)

@tool
def check_domain_security(domain: str) -> str:
    """Analyzes a domain for age, WHOIS flags, and DGA patterns."""
    result = analyze_domain(domain)
    return json.dumps(result)

@tool
def analyze_crypto_wallet(wallet_address: str) -> str:
    """Analyzes a crypto wallet for suspicious transactions like tornado cash interactions or blacklisted addresses."""
    result = run_wallet_analysis(wallet_address)
    return json.dumps(result)

@tool
def check_api_abuse(api_key: str) -> str:
    """Finds if an API key has been used beyond its provisioned rate limits."""
    # Placeholder for a real API usage monitor
    return json.dumps({"status": "flagged", "reason": "Call volume exceeded 10,000/min", "risk": 75})
    
def get_all_tools():
    return [check_ip_reputation, check_domain_security, analyze_crypto_wallet, check_api_abuse]
