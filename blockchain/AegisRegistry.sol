// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisRegistry
 * @notice AEGIS-FLOW Distributed Trust Anchor
 *
 * Stores cryptographic state hashes produced by AEGIS-FLOW nodes.
 * Provides immutable, tamper-proof audit trail of runtime integrity proofs.
 *
 * Deployment: Ethereum Mainnet / Polygon / any EVM chain
 * Version: 1.0.0
 */
contract AegisRegistry {

    // ------------------------------------------------------------------ //
    // Events
    // ------------------------------------------------------------------ //

    event StateRegistered(
        address indexed node,
        bytes32 indexed stateHash,
        uint256 timestamp,
        string severity
    );

    event AlertAnchored(
        address indexed node,
        bytes32 indexed alertId,
        bytes32 stateHash,
        string severity,
        uint256 timestamp
    );

    event NodeAuthorised(address indexed node, address indexed by);
    event NodeRevoked(address indexed node, address indexed by);

    // ------------------------------------------------------------------ //
    // Storage
    // ------------------------------------------------------------------ //

    struct StateRecord {
        address node;
        uint256 timestamp;
        string severity;
        bool exists;
    }

    struct AlertRecord {
        address node;
        bytes32 stateHash;
        string severity;
        uint256 timestamp;
        bool exists;
    }

    address public owner;

    /// @notice Authorised AEGIS nodes that may submit proofs
    mapping(address => bool) public authorisedNodes;

    /// @notice All registered state hashes
    mapping(bytes32 => StateRecord) public stateRecords;

    /// @notice All anchored alert records
    mapping(bytes32 => AlertRecord) public alertRecords;

    /// @notice Per-node submission count (for metrics)
    mapping(address => uint256) public submissionCount;

    bytes32[] private _allStateHashes;
    bytes32[] private _allAlertIds;

    // ------------------------------------------------------------------ //
    // Modifiers
    // ------------------------------------------------------------------ //

    modifier onlyOwner() {
        require(msg.sender == owner, "AegisRegistry: caller is not owner");
        _;
    }

    modifier onlyAuthorised() {
        require(
            authorisedNodes[msg.sender] || msg.sender == owner,
            "AegisRegistry: caller not authorised"
        );
        _;
    }

    // ------------------------------------------------------------------ //
    // Constructor
    // ------------------------------------------------------------------ //

    constructor() {
        owner = msg.sender;
        authorisedNodes[msg.sender] = true;
        emit NodeAuthorised(msg.sender, msg.sender);
    }

    // ------------------------------------------------------------------ //
    // Node Management
    // ------------------------------------------------------------------ //

    /**
     * @notice Authorise a new AEGIS node to submit integrity proofs.
     * @param node The Ethereum address of the node.
     */
    function authoriseNode(address node) external onlyOwner {
        authorisedNodes[node] = true;
        emit NodeAuthorised(node, msg.sender);
    }

    /**
     * @notice Revoke a node's authorisation.
     * @param node The Ethereum address of the node.
     */
    function revokeNode(address node) external onlyOwner {
        authorisedNodes[node] = false;
        emit NodeRevoked(node, msg.sender);
    }

    // ------------------------------------------------------------------ //
    // State Registration
    // ------------------------------------------------------------------ //

    /**
     * @notice Register a runtime state hash on-chain.
     * @param stateHash SHA-256 hash of the AEGIS-FLOW state fingerprint.
     * @param severity  Severity level string ("OK", "WARNING", "CRITICAL").
     */
    function registerState(bytes32 stateHash, string calldata severity)
        external
        onlyAuthorised
    {
        require(stateHash != bytes32(0), "AegisRegistry: zero hash");
        require(!stateRecords[stateHash].exists, "AegisRegistry: hash already registered");

        stateRecords[stateHash] = StateRecord({
            node: msg.sender,
            timestamp: block.timestamp,
            severity: severity,
            exists: true
        });

        _allStateHashes.push(stateHash);
        submissionCount[msg.sender]++;

        emit StateRegistered(msg.sender, stateHash, block.timestamp, severity);
    }

    /**
     * @notice Verify that a state hash is registered and return its record.
     * @param stateHash The hash to verify.
     * @return exists    Whether the hash is registered.
     * @return node      The submitting node.
     * @return timestamp When it was registered.
     * @return severity  Severity at time of registration.
     */
    function verifyState(bytes32 stateHash)
        external
        view
        returns (bool exists, address node, uint256 timestamp, string memory severity)
    {
        StateRecord memory r = stateRecords[stateHash];
        return (r.exists, r.node, r.timestamp, r.severity);
    }

    // ------------------------------------------------------------------ //
    // Alert Anchoring
    // ------------------------------------------------------------------ //

    /**
     * @notice Anchor an alert proof to the chain.
     * @param alertId   Unique 16-byte alert identifier (padded to bytes32).
     * @param stateHash The state hash associated with the alert.
     * @param severity  Severity level ("WARNING" or "CRITICAL").
     */
    function anchorAlert(
        bytes32 alertId,
        bytes32 stateHash,
        string calldata severity
    ) external onlyAuthorised {
        require(alertId != bytes32(0), "AegisRegistry: zero alertId");
        require(!alertRecords[alertId].exists, "AegisRegistry: alert already anchored");

        alertRecords[alertId] = AlertRecord({
            node: msg.sender,
            stateHash: stateHash,
            severity: severity,
            timestamp: block.timestamp,
            exists: true
        });

        _allAlertIds.push(alertId);
        submissionCount[msg.sender]++;

        emit AlertAnchored(msg.sender, alertId, stateHash, severity, block.timestamp);
    }

    // ------------------------------------------------------------------ //
    // Query Helpers
    // ------------------------------------------------------------------ //

    /// @notice Total number of registered state hashes.
    function totalStates() external view returns (uint256) {
        return _allStateHashes.length;
    }

    /// @notice Total number of anchored alerts.
    function totalAlerts() external view returns (uint256) {
        return _allAlertIds.length;
    }

    /**
     * @notice Paginate through all registered state hashes.
     * @param offset Start index.
     * @param limit  Max records to return.
     */
    function getStateHashes(uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory)
    {
        uint256 total = _allStateHashes.length;
        if (offset >= total) return new bytes32[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        bytes32[] memory result = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = _allStateHashes[i];
        }
        return result;
    }

    /**
     * @notice Transfer ownership of the registry.
     * @param newOwner The new owner address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AegisRegistry: zero address");
        owner = newOwner;
    }
}
