// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AgentTrustRegistry
 * @dev A trust registry for autonomous agents. Stores structured cryptographic incident evidence on-chain.
 */
contract AgentTrustRegistry {

    struct Incident {
        bytes32 incidentHash;
        address agent;
        uint severity;
        uint timestamp;
    }

    mapping(address => Incident[]) public incidents;

    event IncidentRecorded(address indexed agent, bytes32 indexed incidentHash, uint severity, uint timestamp);

    /**
     * @dev Record a new security incident against an autonomous agent.
     * @param incidentHash Keccak256 hash of the off-chain evidence object.
     * @param agent The public address / identifier of the offending agent.
     * @param severity The assessed severity score (1-100).
     */
    function recordIncident(
        bytes32 incidentHash,
        address agent,
        uint severity
    ) public {
        Incident memory newIncident = Incident(
            incidentHash,
            agent,
            severity,
            block.timestamp
        );
        
        incidents[agent].push(newIncident);
        
        emit IncidentRecorded(agent, incidentHash, severity, block.timestamp);
    }

    /**
     * @dev Retrieve all incidents for a specific agent.
     */
    function getIncidents(address agent) public view returns (Incident[] memory) {
        return incidents[agent];
    }
}
