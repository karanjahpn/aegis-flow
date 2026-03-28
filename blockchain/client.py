"""
AEGIS-FLOW :: Blockchain Client
=================================
Python client for interacting with the AegisRegistry smart contract
on Ethereum (or any EVM-compatible chain).

Requires:
  pip install web3

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.blockchain")

# ABI extracted from compiled AegisRegistry.sol
AEGIS_REGISTRY_ABI = json.loads("""
[
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true,  "name": "node",      "type": "address"},
      {"indexed": true,  "name": "alertId",   "type": "bytes32"},
      {"indexed": false, "name": "stateHash", "type": "bytes32"},
      {"indexed": false, "name": "severity",  "type": "string"},
      {"indexed": false, "name": "timestamp", "type": "uint256"}
    ],
    "name": "AlertAnchored",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true,  "name": "node",      "type": "address"},
      {"indexed": true,  "name": "stateHash", "type": "bytes32"},
      {"indexed": false, "name": "timestamp", "type": "uint256"},
      {"indexed": false, "name": "severity",  "type": "string"}
    ],
    "name": "StateRegistered",
    "type": "event"
  },
  {
    "inputs": [
      {"name": "alertId",   "type": "bytes32"},
      {"name": "stateHash", "type": "bytes32"},
      {"name": "severity",  "type": "string"}
    ],
    "name": "anchorAlert",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"name": "node", "type": "address"}],
    "name": "authoriseNode",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {"name": "stateHash", "type": "bytes32"},
      {"name": "severity",  "type": "string"}
    ],
    "name": "registerState",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [{"name": "stateHash", "type": "bytes32"}],
    "name": "verifyState",
    "outputs": [
      {"name": "exists",    "type": "bool"},
      {"name": "node",      "type": "address"},
      {"name": "timestamp", "type": "uint256"},
      {"name": "severity",  "type": "string"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalStates",
    "outputs": [{"name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [],
    "name": "totalAlerts",
    "outputs": [{"name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  }
]
""")


class BlockchainClient:
    """
    Ethereum client for AegisRegistry contract interactions.

    Usage:
        client = BlockchainClient(
            rpc_url="https://mainnet.infura.io/v3/YOUR_KEY",
            contract_address="0x...",
            private_key="0x...",
        )
        tx = client.register_state("abc123...", severity="OK")
        print("TX:", tx)
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        gas_limit: int = 200_000,
    ):
        try:
            from web3 import Web3
        except ImportError:
            raise RuntimeError(
                "web3 package not installed. Run: pip install web3"
            )

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {rpc_url}")

        self.account = self.w3.eth.account.from_key(private_key)
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=AEGIS_REGISTRY_ABI,
        )
        self.gas_limit = gas_limit
        logger.info(
            "BlockchainClient ready — node=%s contract=%s",
            self.account.address[:10],
            contract_address[:10],
        )

    # ------------------------------------------------------------------ #
    # Write operations
    # ------------------------------------------------------------------ #

    def register_state(self, state_hash_hex: str, severity: str = "OK") -> str:
        """
        Register a state hash on-chain.

        Args:
            state_hash_hex: 64-char hex string (SHA-256 output).
            severity: "OK", "WARNING", or "CRITICAL".

        Returns:
            Transaction hash string.
        """
        hash_bytes = self._hex_to_bytes32(state_hash_hex)
        tx = self._send_tx(
            self.contract.functions.registerState(hash_bytes, severity)
        )
        logger.info("State registered on-chain: tx=%s", tx)
        return tx

    def anchor_alert(self, alert_id: str, state_hash_hex: str, severity: str) -> str:
        """
        Anchor an alert to the chain.

        Args:
            alert_id: 16-char alert ID string.
            state_hash_hex: 64-char hex state hash.
            severity: "WARNING" or "CRITICAL".

        Returns:
            Transaction hash string.
        """
        alert_id_bytes = self._str_to_bytes32(alert_id)
        hash_bytes = self._hex_to_bytes32(state_hash_hex)
        tx = self._send_tx(
            self.contract.functions.anchorAlert(alert_id_bytes, hash_bytes, severity)
        )
        logger.info("Alert anchored on-chain: tx=%s", tx)
        return tx

    # ------------------------------------------------------------------ #
    # Read operations
    # ------------------------------------------------------------------ #

    def verify_state(self, state_hash_hex: str) -> dict:
        """
        Query the contract for a registered state hash.

        Returns:
            {exists, node, timestamp, severity}
        """
        hash_bytes = self._hex_to_bytes32(state_hash_hex)
        exists, node, ts, severity = self.contract.functions.verifyState(
            hash_bytes
        ).call()
        return {
            "exists": exists,
            "node": node,
            "timestamp": ts,
            "severity": severity,
        }

    def total_states(self) -> int:
        return self.contract.functions.totalStates().call()

    def total_alerts(self) -> int:
        return self.contract.functions.totalAlerts().call()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _send_tx(self, fn) -> str:
        """Build, sign, and send a transaction. Returns tx hash."""
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = fn.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": self.w3.eth.gas_price,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
        return tx_hash.hex()

    @staticmethod
    def _hex_to_bytes32(hex_str: str) -> bytes:
        """Convert 64-char hex string to bytes32."""
        clean = hex_str.lstrip("0x")
        if len(clean) > 64:
            clean = clean[:64]
        return bytes.fromhex(clean.zfill(64))

    @staticmethod
    def _str_to_bytes32(s: str) -> bytes:
        """Encode a short string to bytes32 (right-padded with zeros)."""
        encoded = s.encode()[:32]
        return encoded + b"\x00" * (32 - len(encoded))
