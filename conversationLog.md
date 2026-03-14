# Sentinel — Conversation & Build Narrative
**Synthesis Competition Project**

We transformed a basic sequential Prompt Chain SOC prototype into **Sentinel**, a top-tier Trust & Incident Attestation infrastructure for autonomous agents.

## 1. The Starting Point (Weaknesses Identified)
The initial repository provided was weak:
- The "multi-agent" framework was actually a hardcoded prompt chain using an uncompilable package constraint.
- Investigation data was completely mocked and didn't allow the agents to think.
- There was no cryptographic trust or verifiable attestation of agent actions.
- The repository was cluttered with `venv` and unrelated files.

## 2. Pivot & Architecture Design: Sentinel
We pivoted the concept to solve an urgent problem in the web3 x AI space: **How do we trust autonomous agents?**
If an agent trades on your behalf or manages your wallet, you need immutable proof of its behavior.

We designed a 5-layer autonomous pipeline using LangChain structured outputs:
1. **Detection**: Streams agent action logs and extracts structured Pydantic objects identifying `SuspiciousEntities`.
2. **Investigation**: Given the entities, this agent is granted **Tools** (IP Rep, Wallet Analyzer) and must autonomously decide how to gather evidence.
3. **Evidence**: Converts the inputs into an Ethereum-standard Keccak256 hash.
4. **Attestation**: A Web3.py agent that takes the evidence hash and writes it to a Smart Contract deployed on Base Sepolia Testnet.
5. **Reporting**: Synthesizes a human-readable Trust report.

## 3. Blockchain Integration
We utilized Hardhat to write the `AgentTrustRegistry.sol` smart contract:
```solidity
struct Incident {
    bytes32 incidentHash;
    address agent;
    uint severity;
    uint timestamp;
}
```
This enables the Sentinel system to immutably penalize or clear agents based on their behavior stream.

## 4. Evaluation Framework
To prove the system works dynamically, we built an evaluation runner with 10 simulated events (normal, suspicious, and malicious). 
The `metrics.py` script automatically runs these payloads through the FastAPI orchestrator and calculates Detection Accuracy and False Positive Rates based on the Agent's reasoning.

## 5. Result
The system is now a verifiable, autonomous, on-chain truth machine. It went from a static LLM text generator to a Web3-integrated trust layer with measurable KPIs.
