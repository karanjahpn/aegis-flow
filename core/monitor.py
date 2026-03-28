"""
AEGIS-FLOW :: Continuous Monitor
==================================
Runs an infinite monitoring loop that:
  1. Captures current state fingerprint
  2. Compares against verified baseline
  3. Triggers alerts and optional self-healing on drift

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import time
import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from core.fingerprint import (
    compute_state_fingerprint,
    generate_nonce,
    compare_states,
)
from core.alert import AlertManager, AlertSeverity
from enclave.sim import EnclaveSimulator

logger = logging.getLogger("aegis.monitor")


@dataclass
class MonitorConfig:
    """Configuration for the runtime monitor."""
    interval_seconds: float = 2.0
    max_consecutive_violations: int = 3
    auto_heal: bool = True
    alert_hooks: List[Callable] = field(default_factory=list)
    blockchain_enabled: bool = False
    blockchain_rpc_url: str = ""
    blockchain_contract: str = ""
    blockchain_private_key: str = ""


class RuntimeMonitor:
    """
    Core monitoring loop for AEGIS-FLOW.

    Usage:
        monitor = RuntimeMonitor(baseline, config)
        monitor.start()   # non-blocking (spawns thread)
        monitor.stop()
    """

    def __init__(self, baseline: dict, config: MonitorConfig):
        self.baseline = baseline
        self.config = config
        self.enclave = EnclaveSimulator()
        self.alert_manager = AlertManager(hooks=config.alert_hooks)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._violation_count = 0
        self._check_count = 0
        self._history: List[dict] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def start(self):
        """Start the monitor in a background thread."""
        if self._running:
            logger.warning("Monitor already running.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="AegisMonitor", daemon=True
        )
        self._thread.start()
        logger.info("AEGIS-FLOW Monitor started (interval=%.1fs)", self.config.interval_seconds)

    def stop(self):
        """Stop the monitor gracefully."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("AEGIS-FLOW Monitor stopped. Checks=%d Violations=%d",
                    self._check_count, self._violation_count)

    def run_once(self) -> dict:
        """Run a single integrity check. Returns the comparison result."""
        return self._check()

    def status(self) -> dict:
        """Return a summary of monitoring status."""
        return {
            "running": self._running,
            "checks_performed": self._check_count,
            "violations_detected": self._violation_count,
            "consecutive_violations": self._violation_count,
            "last_n_events": self._history[-10:],
        }

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _loop(self):
        while self._running:
            try:
                self._check()
            except Exception as exc:
                logger.error("Monitor check error: %s", exc, exc_info=True)
            time.sleep(self.config.interval_seconds)

    def _check(self) -> dict:
        self._check_count += 1
        nonce = generate_nonce()
        current = compute_state_fingerprint(nonce)

        result = compare_states(self.baseline, current)
        result["check_number"] = self._check_count
        result["timestamp"] = current["timestamp"]

        # Enclave verification
        enclave_result = self.enclave.verify(
            state_hash=current["state_hash"],
            nonce=nonce,
            baseline_hash=self.baseline["state_hash"],
        )
        result["enclave_verdict"] = enclave_result

        self._history.append(result)

        if result["match"] and enclave_result["valid"]:
            self._violation_count = 0
            logger.debug("[CHECK #%d] ✅ Integrity OK — hash=%s",
                         self._check_count, current["state_hash"][:16])
        else:
            self._violation_count += 1
            logger.warning("[CHECK #%d] ⚠️  VIOLATION — drift=%s enclave=%s",
                           self._check_count,
                           [d["field"] for d in result.get("drift", [])],
                           enclave_result.get("reason", ""))

            severity = (
                AlertSeverity.CRITICAL
                if self._violation_count >= self.config.max_consecutive_violations
                else AlertSeverity.WARNING
            )

            alert = self.alert_manager.fire(
                severity=severity,
                state_hash=current["state_hash"],
                drift=result.get("drift", []),
                enclave_result=enclave_result,
                signed_by=self.enclave.sign(current["state_hash"]),
                check_number=self._check_count,
            )

            # Optional: push to blockchain
            if self.config.blockchain_enabled:
                self._anchor_to_chain(alert)

            # Optional: self-heal
            if self.config.auto_heal and severity == AlertSeverity.CRITICAL:
                self._self_heal()

        return result

    def _anchor_to_chain(self, alert: dict):
        """Push alert hash to Ethereum blockchain."""
        try:
            from blockchain.client import BlockchainClient
            client = BlockchainClient(
                rpc_url=self.config.blockchain_rpc_url,
                contract_address=self.config.blockchain_contract,
                private_key=self.config.blockchain_private_key,
            )
            tx_hash = client.register_state(alert["state_hash"])
            logger.info("Anchored to blockchain: tx=%s", tx_hash)
        except Exception as exc:
            logger.error("Blockchain anchor failed: %s", exc)

    def _self_heal(self):
        """Trigger self-healing response."""
        logger.critical("🛡️  SELF-HEAL triggered — resetting baseline & alerting operators")
        # In production: kill child processes, rotate keys, redirect traffic
        # For v1: log and re-baseline
        nonce = generate_nonce()
        self.baseline = compute_state_fingerprint(nonce)
        logger.info("Baseline re-established: hash=%s", self.baseline["state_hash"][:16])
