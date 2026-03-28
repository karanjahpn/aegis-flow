/**
 * AEGIS-FLOW :: AegisRegistry Smart Contract Tests
 * ==================================================
 * Tests the AegisRegistry Solidity contract using Hardhat + ethers.js
 *
 * Run: npx hardhat test
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisRegistry", function () {
  let registry;
  let owner, node1, node2, stranger;

  // Sample state hashes (bytes32)
  const HASH_A = ethers.utils.formatBytes32String("state_hash_A");
  const HASH_B = ethers.utils.formatBytes32String("state_hash_B");
  const ALERT_ID = ethers.utils.formatBytes32String("alert_0001");

  beforeEach(async function () {
    [owner, node1, node2, stranger] = await ethers.getSigners();
    const AegisRegistry = await ethers.getContractFactory("AegisRegistry");
    registry = await AegisRegistry.deploy();
    await registry.deployed();
  });

  // ------------------------------------------------------------------ //
  // Deployment
  // ------------------------------------------------------------------ //

  describe("Deployment", function () {
    it("sets the deployer as owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("auto-authorises the owner", async function () {
      expect(await registry.authorisedNodes(owner.address)).to.be.true;
    });

    it("starts with zero state records", async function () {
      expect(await registry.totalStates()).to.equal(0);
    });
  });

  // ------------------------------------------------------------------ //
  // Node Management
  // ------------------------------------------------------------------ //

  describe("Node Management", function () {
    it("owner can authorise a new node", async function () {
      await expect(registry.authoriseNode(node1.address))
        .to.emit(registry, "NodeAuthorised")
        .withArgs(node1.address, owner.address);
      expect(await registry.authorisedNodes(node1.address)).to.be.true;
    });

    it("owner can revoke a node", async function () {
      await registry.authoriseNode(node1.address);
      await expect(registry.revokeNode(node1.address))
        .to.emit(registry, "NodeRevoked")
        .withArgs(node1.address, owner.address);
      expect(await registry.authorisedNodes(node1.address)).to.be.false;
    });

    it("non-owner cannot authorise nodes", async function () {
      await expect(
        registry.connect(stranger).authoriseNode(node1.address)
      ).to.be.revertedWith("AegisRegistry: caller is not owner");
    });
  });

  // ------------------------------------------------------------------ //
  // State Registration
  // ------------------------------------------------------------------ //

  describe("State Registration", function () {
    it("authorised node can register a state hash", async function () {
      await expect(registry.registerState(HASH_A, "OK"))
        .to.emit(registry, "StateRegistered")
        .withArgs(owner.address, HASH_A, anyValue, "OK");

      expect(await registry.totalStates()).to.equal(1);
    });

    it("verifyState returns correct record", async function () {
      await registry.registerState(HASH_A, "WARNING");
      const [exists, node, , severity] = await registry.verifyState(HASH_A);
      expect(exists).to.be.true;
      expect(node).to.equal(owner.address);
      expect(severity).to.equal("WARNING");
    });

    it("verifyState returns exists=false for unknown hash", async function () {
      const [exists] = await registry.verifyState(HASH_B);
      expect(exists).to.be.false;
    });

    it("cannot register the same hash twice", async function () {
      await registry.registerState(HASH_A, "OK");
      await expect(
        registry.registerState(HASH_A, "OK")
      ).to.be.revertedWith("AegisRegistry: hash already registered");
    });

    it("cannot register zero hash", async function () {
      await expect(
        registry.registerState(ethers.constants.HashZero, "OK")
      ).to.be.revertedWith("AegisRegistry: zero hash");
    });

    it("unauthorised address cannot register state", async function () {
      await expect(
        registry.connect(stranger).registerState(HASH_A, "OK")
      ).to.be.revertedWith("AegisRegistry: caller not authorised");
    });

    it("authorised node (non-owner) can register state", async function () {
      await registry.authoriseNode(node1.address);
      await expect(
        registry.connect(node1).registerState(HASH_B, "CRITICAL")
      ).to.emit(registry, "StateRegistered");
    });

    it("tracks submission count per node", async function () {
      await registry.registerState(HASH_A, "OK");
      expect(await registry.submissionCount(owner.address)).to.equal(1);
    });
  });

  // ------------------------------------------------------------------ //
  // Alert Anchoring
  // ------------------------------------------------------------------ //

  describe("Alert Anchoring", function () {
    it("can anchor an alert", async function () {
      await expect(registry.anchorAlert(ALERT_ID, HASH_A, "CRITICAL"))
        .to.emit(registry, "AlertAnchored")
        .withArgs(owner.address, ALERT_ID, HASH_A, "CRITICAL", anyValue);

      expect(await registry.totalAlerts()).to.equal(1);
    });

    it("cannot anchor the same alertId twice", async function () {
      await registry.anchorAlert(ALERT_ID, HASH_A, "WARNING");
      await expect(
        registry.anchorAlert(ALERT_ID, HASH_A, "WARNING")
      ).to.be.revertedWith("AegisRegistry: alert already anchored");
    });

    it("alert record stores correct data", async function () {
      await registry.anchorAlert(ALERT_ID, HASH_A, "CRITICAL");
      const record = await registry.alertRecords(ALERT_ID);
      expect(record.exists).to.be.true;
      expect(record.stateHash).to.equal(HASH_A);
      expect(record.severity).to.equal("CRITICAL");
      expect(record.node).to.equal(owner.address);
    });
  });

  // ------------------------------------------------------------------ //
  // Pagination
  // ------------------------------------------------------------------ //

  describe("Pagination", function () {
    it("getStateHashes paginates correctly", async function () {
      await registry.registerState(HASH_A, "OK");
      await registry.registerState(HASH_B, "WARNING");

      const page = await registry.getStateHashes(0, 2);
      expect(page.length).to.equal(2);
      expect(page[0]).to.equal(HASH_A);
      expect(page[1]).to.equal(HASH_B);
    });

    it("getStateHashes returns empty for out-of-range offset", async function () {
      const page = await registry.getStateHashes(100, 10);
      expect(page.length).to.equal(0);
    });
  });

  // ------------------------------------------------------------------ //
  // Ownership Transfer
  // ------------------------------------------------------------------ //

  describe("Ownership", function () {
    it("owner can transfer ownership", async function () {
      await registry.transferOwnership(node1.address);
      expect(await registry.owner()).to.equal(node1.address);
    });

    it("cannot transfer to zero address", async function () {
      await expect(
        registry.transferOwnership(ethers.constants.AddressZero)
      ).to.be.revertedWith("AegisRegistry: zero address");
    });
  });
});

// Chai helper — match any value in event args
const anyValue = require("@nomicfoundation/hardhat-chai-matchers/withArgs")
  ?.anyValue ?? (() => true);
