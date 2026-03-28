"""
AEGIS-FLOW :: Alert Manager
=============================
Manages alert creation, signing, routing, and delivery
through configurable hooks (console, file, webhook, etc.)

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import json
import time
import hashlib
import logging
import enum
from typing import Callable, List, Optional

logger = logging.getLogger("aegis.alert")


class AlertSeverity(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertManager:
    """
    Manages all alert dispatch for AEGIS-FLOW.

    Supports pluggable hooks — any callable that accepts an alert dict.
    Built-in hooks: console, file.
    """

    def __init__(self, hooks: Optional[List[Callable]] = None):
        self._hooks = hooks or []
        self._alerts: List[dict] = []
        # Always add console hook
        self._hooks.insert(0, self._console_hook)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def add_hook(self, hook: Callable):
        """Register a new alert hook."""
        self._hooks.append(hook)

    def fire(
        self,
        severity: AlertSeverity,
        state_hash: str,
        drift: list,
        enclave_result: dict,
        signed_by: str,
        check_number: int,
    ) -> dict:
        """
        Create, sign, and dispatch an alert.

        Returns the alert dict (with embedded signature).
        """
        alert = self._build_alert(
            severity=severity,
            state_hash=state_hash,
            drift=drift,
            enclave_result=enclave_result,
            signed_by=signed_by,
            check_number=check_number,
        )
        self._alerts.append(alert)

        for hook in self._hooks:
            try:
                hook(alert)
            except Exception as exc:
                logger.error("Alert hook %s failed: %s", hook.__name__, exc)

        return alert

    def get_history(self, last_n: int = 50) -> List[dict]:
        """Return the last N alerts."""
        return self._alerts[-last_n:]

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _build_alert(self, **kwargs) -> dict:
        timestamp = time.time()
        alert_id = hashlib.sha256(
            f"{timestamp}{kwargs['state_hash']}".encode()
        ).hexdigest()[:16]

        alert = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "severity": kwargs["severity"].value,
            "state_hash": kwargs["state_hash"],
            "drift_fields": [d.get("field") for d in kwargs["drift"]],
            "drift_detail": kwargs["drift"],
            "enclave_verdict": kwargs["enclave_result"],
            "signed_by_enclave": kwargs["signed_by"],
            "check_number": kwargs["check_number"],
        }

        # Self-sign the alert envelope
        alert["alert_signature"] = self._sign_alert(alert)
        return alert

    def _sign_alert(self, alert: dict) -> str:
        """Create a deterministic signature of the alert envelope."""
        payload = json.dumps({
            "alert_id": alert["alert_id"],
            "state_hash": alert["state_hash"],
            "severity": alert["severity"],
            "timestamp": alert["timestamp"],
        }, sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()

    def _console_hook(self, alert: dict):
        """Default: print alert to console."""
        sep = "=" * 60
        lines = [
            sep,
            f"🚨 AEGIS-FLOW ALERT [{alert['severity']}]",
            f"   ID        : {alert['alert_id']}",
            f"   Check #   : {alert['check_number']}",
            f"   State Hash: {alert['state_hash'][:32]}...",
            f"   Drift     : {', '.join(alert['drift_fields']) or 'none'}",
            f"   Enclave   : {alert['enclave_verdict'].get('reason', 'ok')}",
            f"   Signed    : {alert['alert_signature'][:24]}...",
            sep,
        ]
        print("\n".join(lines))


# ------------------------------------------------------------------ #
# Built-in hook helpers
# ------------------------------------------------------------------ #

def file_hook(filepath: str) -> Callable:
    """
    Returns a hook that appends alerts as JSON lines to a file.

    Usage:
        manager.add_hook(file_hook("/var/log/aegis/alerts.jsonl"))
    """
    def _hook(alert: dict):
        with open(filepath, "a") as f:
            f.write(json.dumps(alert) + "\n")
    _hook.__name__ = f"file_hook({filepath})"
    return _hook


def webhook_hook(url: str) -> Callable:
    """
    Returns a hook that POSTs alerts to a webhook URL.

    Usage:
        manager.add_hook(webhook_hook("https://hooks.example.com/aegis"))
    """
    import urllib.request

    def _hook(alert: dict):
        payload = json.dumps(alert).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info("Webhook delivered: status=%d", resp.status)
    _hook.__name__ = f"webhook_hook({url})"
    return _hook
