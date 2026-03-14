import os
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from api.schemas import EvidenceObject, IncidentDetection, AttestationResult


def get_contract_abi():
    return [
        {
            "inputs": [
                {"internalType": "bytes32", "name": "incidentHash", "type": "bytes32"},
                {"internalType": "address", "name": "agent", "type": "address"},
                {"internalType": "uint256", "name": "severity", "type": "uint256"}
            ],
            "name": "recordIncident",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]


def _is_blockchain_configured() -> bool:
    """Return True only if both the private key and contract address are real values."""
    pk = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    ca = os.getenv("CONTRACT_ADDRESS", "")
    return (
        bool(pk) and pk != "your_metamask_private_key_here"
        and bool(ca) and ca != "0x_deployed_contract_address_here"
    )


def publish_attestation(detection: IncidentDetection, evidence: Optional[EvidenceObject] = None) -> AttestationResult:
    """
    Submits the incident evidence hash to the AgentTrustRegistry smart contract
    on Base Sepolia Testnet.

    If blockchain credentials are missing or invalid, returns an explicit MOCK
    result — the mode field is always set so the UI can label it correctly.
    """
    if not evidence:
        return AttestationResult(
            transaction_hash="N/A",
            contract_address="N/A",
            status="Failed",
            attestation_mode="REAL"
        )

    if not _is_blockchain_configured():
        print(f"[Attestation] ⚠️  Blockchain not configured — returning MOCK attestation for {detection.incident_id}")
        return AttestationResult(
            transaction_hash="N/A — Mock Mode",
            contract_address="N/A — Mock Mode",
            status="Mock",
            attestation_mode="MOCK",
        )

    rpc_url = os.getenv("BASE_SEPOLIA_RPC", "https://sepolia.base.org")
    private_key = os.getenv("DEPLOYER_PRIVATE_KEY")
    contract_address_raw = os.getenv("CONTRACT_ADDRESS")

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        account = w3.eth.account.from_key(private_key)
        contract_address = w3.to_checksum_address(contract_address_raw)
        contract = w3.eth.contract(address=contract_address, abi=get_contract_abi())

        # Convert agent_id to a valid EVM address
        agent_addr = (
            w3.to_checksum_address(detection.agent_id)
            if w3.is_address(detection.agent_id)
            else w3.eth.account.create().address
        )

        # Convert hex hash string → bytes32
        # evidence.incident_hash is "0x..." from keccak
        incident_hash_bytes = bytes.fromhex(evidence.incident_hash.removeprefix("0x"))

        tx = contract.functions.recordIncident(
            incident_hash_bytes,
            agent_addr,
            detection.severity,
        ).build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gasPrice": w3.eth.gas_price,
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        print(f"[Attestation] ✅ On-chain. TX: {receipt.transactionHash.hex()}")
        return AttestationResult(
            transaction_hash=receipt.transactionHash.hex(),
            contract_address=contract_address,
            status="Success" if receipt.status == 1 else "Failed",
            attestation_mode="REAL",
        )

    except Exception as e:
        print(f"[Attestation] ❌ On-chain submission failed: {e}")
        return AttestationResult(
            transaction_hash=f"Error: {str(e)}",
            contract_address=contract_address_raw or "Unknown",
            status="Failed",
            attestation_mode="REAL",  # Attempted real but failed — not a mock
        )
