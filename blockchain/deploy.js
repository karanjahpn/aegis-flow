/**
 * AEGIS-FLOW :: AegisRegistry Deployment Script
 * ================================================
 * Deploys the AegisRegistry contract using Hardhat + ethers.js
 *
 * Usage:
 *   npx hardhat run blockchain/deploy.js --network <network>
 *
 * Networks (configure in hardhat.config.js):
 *   localhost  — local Hardhat node
 *   goerli     — Ethereum testnet
 *   polygon    — Polygon mainnet
 *   mainnet    — Ethereum mainnet (expensive!)
 */

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("=".repeat(60));
  console.log("AEGIS-FLOW :: Deploying AegisRegistry");
  console.log("=".repeat(60));
  console.log("Deployer :", deployer.address);
  console.log(
    "Balance  :",
    ethers.utils.formatEther(await deployer.getBalance()),
    "ETH"
  );

  const AegisRegistry = await ethers.getContractFactory("AegisRegistry");
  const registry = await AegisRegistry.deploy();
  await registry.deployed();

  console.log("\n✅ AegisRegistry deployed!");
  console.log("   Contract address :", registry.address);
  console.log("   Block            :", registry.deployTransaction.blockNumber);
  console.log("   TX hash          :", registry.deployTransaction.hash);
  console.log("\nAdd to .env:");
  console.log(`   AEGIS_CONTRACT_ADDRESS=${registry.address}`);

  // Verify deployer is auto-authorised
  const isAuth = await registry.authorisedNodes(deployer.address);
  console.log("   Deployer authorised:", isAuth);

  return registry.address;
}

main()
  .then((addr) => {
    console.log("\nDone:", addr);
    process.exit(0);
  })
  .catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
  });
