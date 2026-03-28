"""
AEGIS-FLOW :: Test Suite
==========================
Tests for:
  - State fingerprinting
  - Comparison / drift detection
  - Enclave simulation
  - Alert manager
  - Monitor (single-run)

Run:
    pip install pytest
    pytest tests/ -v

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import sys
import time
import json
import hashlib
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is on path
sys.path.insert(0, ".")

from core.fingerprint import (
    compute_baseline,
    compute_state_fingerprint,
    compare_states,
    generate_nonce,
)
from core.alert import AlertManager, AlertSeverity, file_hook
from enclave.sim import EnclaveSimulator


# ====================================================================== #
# Fingerprint Tests
# ====================================================================== #

class TestFingerprint(unittest.TestCase):

    def test_baseline_has_state_hash(self):
        baseline = compute_baseline()
        self.assertIn("state_hash", baseline)
        self.assertEqual(len(baseline["state_hash"]), 64)  # SHA-256 hex

    def test_state_hash_is_deterministic_structure(self):
        """Two calls produce different nonces hence different hashes."""
        b1 = compute_baseline()
        b2 = compute_baseline()
        # Hashes will differ because nonces differ
        self.assertNotEqual(b1["state_hash"], b2["state_hash"])

    def test_nonce_is_unique(self):
        nonces = {generate_nonce() for _ in range(100)}
        self.assertEqual(len(nonces), 100)

    def test_fingerprint_has_required_components(self):
        nonce = generate_nonce()
        fp = compute_state_fingerprint(nonce)
        self.assertIn("state_hash", fp)
        self.assertIn("timestamp", fp)
        self.assertIn("nonce", fp)
        self.assertIn("components", fp)
        components = fp["components"]
        self.assertIn("process", components)
        self.assertIn("modules_hash", components)
        self.assertIn("env_hash", components)
        self.assertIn("platform", components)

    def test_compare_identical_states_match(self):
        """When baseline == current (same nonce), should match."""
        nonce = generate_nonce()
        fp = compute_state_fingerprint(nonce)
        # Compare fp against itself
        result = compare_states(fp, fp)
        self.assertTrue(result["match"])
        self.assertEqual(result["drift"], [])


class TestDriftDetection(unittest.TestCase):

    def test_detects_module_drift(self):
        """Manually craft two fingerprints with different module hashes."""
        nonce = generate_nonce()
        base = compute_state_fingerprint(nonce)
        current = compute_state_fingerprint(generate_nonce())

        # Simulate a changed module hash
        current_modified = json.loads(json.dumps(current))
        current_modified["components"]["modules_hash"] = "deadbeef" * 8

        result = compare_states(base, current_modified)
        drift_fields = [d["field"] for d in result["drift"]]
        self.assertIn("modules_hash", drift_fields)

    def test_no_drift_when_within_tolerance(self):
        """Memory delta within 5MB should not flag as drift."""
        nonce = generate_nonce()
        base = compute_state_fingerprint(nonce)
        current = json.loads(json.dumps(base))

        # Add 1MB drift — within tolerance
        current["components"]["process"]["memory_rss"] += 1 * 1024 * 1024
        current["nonce"] = generate_nonce()

        result = compare_states(base, current)
        drift_fields = [d["field"] for d in result["drift"]]
        self.assertNotIn("memory_rss", drift_fields)

    def test_detects_large_memory_drift(self):
        """Memory delta > 5MB should flag drift."""
        nonce = generate_nonce()
        base = compute_state_fingerprint(nonce)
        current = json.loads(json.dumps(base))

        # Add 10MB drift
        current["components"]["process"]["memory_rss"] += 10 * 1024 * 1024

        result = compare_states(base, current)
        drift_fields = [d["field"] for d in result["drift"]]
        self.assertIn("memory_rss", drift_fields)


# ====================================================================== #
# Enclave Tests
# ====================================================================== #

class TestEnclaveSimulator(unittest.TestCase):

    def setUp(self):
        self.enc = EnclaveSimulator()

    def test_verify_valid_state(self):
        baseline = compute_baseline()
        self.enc.seal_baseline(baseline["state_hash"])

        result = self.enc.verify(
            state_hash=baseline["state_hash"],
            nonce=generate_nonce(),
            baseline_hash=baseline["state_hash"],
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["reason"], "ok")
        self.assertIsNotNone(result["token"])

    def test_reject_wrong_state(self):
        baseline = compute_baseline()
        self.enc.seal_baseline(baseline["state_hash"])

        result = self.enc.verify(
            state_hash="wrong" * 12 + "hash",
            nonce=generate_nonce(),
            baseline_hash=baseline["state_hash"],
        )
        self.assertFalse(result["valid"])

    def test_reject_replay_nonce(self):
        baseline = compute_baseline()
        self.enc.seal_baseline(baseline["state_hash"])
        nonce = generate_nonce()

        # First use — OK
        r1 = self.enc.verify(baseline["state_hash"], nonce, baseline["state_hash"])
        self.assertTrue(r1["valid"])

        # Second use — replay
        r2 = self.enc.verify(baseline["state_hash"], nonce, baseline["state_hash"])
        self.assertFalse(r2["valid"])
        self.assertIn("replay", r2["reason"])

    def test_sign_produces_consistent_length(self):
        sig = self.enc.sign("hello aegis")
        self.assertEqual(len(sig), 64)  # HMAC-SHA256 hex = 64 chars

    def test_attest_returns_report(self):
        report = self.enc.attest()
        self.assertIn("enclave_mode", report)
        self.assertIn("report_signature", report)
        self.assertEqual(report["enclave_mode"], "simulation")


# ====================================================================== #
# Alert Manager Tests
# ====================================================================== #

class TestAlertManager(unittest.TestCase):

    def test_fire_returns_alert_dict(self):
        mgr = AlertManager()
        enc = EnclaveSimulator()
        nonce = generate_nonce()
        fp = compute_state_fingerprint(nonce)

        alert = mgr.fire(
            severity=AlertSeverity.WARNING,
            state_hash=fp["state_hash"],
            drift=[{"field": "memory_rss", "baseline": 1000, "current": 2000}],
            enclave_result={"valid": False, "reason": "mismatch"},
            signed_by=enc.sign(fp["state_hash"]),
            check_number=1,
        )

        self.assertIn("alert_id", alert)
        self.assertIn("alert_signature", alert)
        self.assertEqual(alert["severity"], "WARNING")
        self.assertEqual(len(alert["alert_id"]), 16)

    def test_hook_is_called(self):
        called = []
        def my_hook(alert):
            called.append(alert)

        mgr = AlertManager(hooks=[my_hook])
        enc = EnclaveSimulator()
        fp = compute_state_fingerprint(generate_nonce())

        mgr.fire(
            severity=AlertSeverity.CRITICAL,
            state_hash=fp["state_hash"],
            drift=[],
            enclave_result={"valid": False, "reason": "test"},
            signed_by=enc.sign(fp["state_hash"]),
            check_number=1,
        )
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0]["severity"], "CRITICAL")

    def test_get_history(self):
        mgr = AlertManager()
        enc = EnclaveSimulator()

        for i in range(5):
            fp = compute_state_fingerprint(generate_nonce())
            mgr.fire(
                severity=AlertSeverity.INFO,
                state_hash=fp["state_hash"],
                drift=[],
                enclave_result={"valid": True, "reason": "ok"},
                signed_by=enc.sign(fp["state_hash"]),
                check_number=i + 1,
            )

        history = mgr.get_history(last_n=3)
        self.assertEqual(len(history), 3)


# ====================================================================== #
# Monitor Integration Tests
# ====================================================================== #

class TestMonitorIntegration(unittest.TestCase):

    def test_single_run_returns_result(self):
        from core.monitor import RuntimeMonitor, MonitorConfig
        baseline = compute_baseline()
        config = MonitorConfig(auto_heal=False)
        monitor = RuntimeMonitor(baseline=baseline, config=config)

        result = monitor.run_once()
        self.assertIn("match", result)
        self.assertIn("check_number", result)
        self.assertEqual(result["check_number"], 1)

    def test_status_after_checks(self):
        from core.monitor import RuntimeMonitor, MonitorConfig
        baseline = compute_baseline()
        config = MonitorConfig(auto_heal=False)
        monitor = RuntimeMonitor(baseline=baseline, config=config)

        for _ in range(3):
            monitor.run_once()

        status = monitor.status()
        self.assertEqual(status["checks_performed"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
