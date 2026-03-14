"""
Sentinel Domain Analysis Tool
Analyzes domains for age, WHOIS flags, and DGA patterns.
"""
import re

def analyze_domain(domain: str) -> dict:
    """
    Performs security analysis on a domain.
    """
    # Simulated DGA (Domain Generation Algorithm) detection
    is_dga = len(re.findall(r'[0-9]', domain)) > 3 and len(domain) > 15
    
    # Mock WHOIS data
    suspicious_domains = {
        "malicious-c2.com": {"age_days": 2, "registrar": "Unknown", "risk": "CRITICAL"},
        "proxy-tunnel.io": {"age_days": 15, "registrar": "PrivacyProtected", "risk": "HIGH"},
    }
    
    result = suspicious_domains.get(domain, {
        "age_days": 1200, 
        "registrar": "GoDaddy", 
        "risk": "LOW"
    })
    
    if is_dga:
        result["risk"] = "HIGH"
        result["notes"] = "DGA-like pattern detected"
        
    return result
