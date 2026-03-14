import hashlib
import json
from api.schemas import IncidentDetection, InvestigationResult, EvidenceObject
from eth_hash.auto import keccak

def generate_evidence(detection: IncidentDetection, investigation: Optional[InvestigationResult] = None) -> EvidenceObject:
    """
    Takes the detection and investigation structured data, bundles it into a 'full report',
    and generates an integrity hash using Ethereum's Keccak256 standard.
    """
    
    # Create the full off-chain document text
    full_report_dict = {
        "incident": detection.model_dump(),
        "investigation": investigation.model_dump() if investigation else "Skipped by Orchestrator"
    }
    
    # Serialize to deterministic JSON string
    report_json = json.dumps(full_report_dict, separators=(',', ':'), sort_keys=True)
    
    # Generate Keccak256 incident hash (to store on blockchain)
    # web3.py's Web3.keccak can also do this, but eth_hash is standard
    k = keccak(report_json.encode('utf-8'))
    incident_hash_hex = "0x" + k.hex()
    
    # Return the cryptographic Evidence Object
    return EvidenceObject(
        incident_hash=incident_hash_hex,
        evidence_location="offchain_database://local/reports/" + detection.incident_id + ".json",
        integrity_hash=hashlib.sha256(report_json.encode('utf-8')).hexdigest()
    )
