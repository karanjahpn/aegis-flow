"""
AEGIS-FLOW :: Enclave Simulator
=================================
Simulates a Trusted Execution Environment (TEE) for development/testing.

In production this module is replaced by:
  - Intel SGX SDK calls
  - ARM TrustZone secure world calls
  - AWS Nitro Enclave SDK

The simulator mirrors the enclave interface exactly so the rest of the
system requires zero changes when swapping in real hardware.

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import hmac
import time
import hashlib
import json
import os
import logging
from typing import Optional

logger = logging.getLogger("aegis.enclave")

# In a real TEE this key never leaves the enclave.
# Here it's generated fresh per process instance (not persisted).
_ENCLAVE_SECRET = os.urandom(32)

# How long a nonce is considered fresh (seconds)
_NONCE_TTL_SECONDS = 30


class EnclaveSimulator:
    """
    Simulates a TEE enclave with:
      - HMAC-based signing (mirrors attestation token)
      - Nonce freshness validation
      - Baseline state custody
    """

    def __init__(self, secret: Optional[bytes] = None):
        self._secret = secret or _ENCLAVE_SECRET
        self._seen_nonces: dict[str, float] = {}
        self._baseline_hash: Optional[str] = None
        logger.info("Enclave initialised (simulation mode). Secret: %s...",
                    self._secret.hex()[:8])

    # ------------------------------------------------------------------ #
    # Public API  (mirrors what a real SGX/TrustZone enclave exposes)
    # ------------------------------------------------------------------ #

    def seal_baseline(self, baseline_hash: str):
        """
        Seal (store) the baseline hash inside the enclave.
        In production: sealed with platform key, stored in enclave memory.
        """
        self._baseline_hash = baseline_hash
        logger.info("Enclave: baseline sealed — hash=%s", baseline_hash[:16])

    def verify(self, state_hash: str, nonce: str, baseline_hash: str) -> dict:
        """
        Verify a runtime state against the sealed baseline.

        Checks:
          1. Nonce is fresh (not replayed, not expired)
          2. State hash matches baseline

        Returns:
          {valid: bool, reason: str, token: str|None}
        """
        # 1. Nonce check
        nonce_result = self._validate_nonce(nonce)
        if not nonce_result["valid"]:
            return {"valid": False, "reason": nonce_result["reason"], "token": None}

        # 2. Baseline match
        effective_baseline = self._baseline_hash or baseline_hash
        if state_hash != effective_baseline:
            return {
                "valid": False,
                "reason": f"state_hash mismatch (expected …{effective_baseline[-8:]}, got …{state_hash[-8:]})",
                "token": None,
            }

        # 3. Issue attestation token
        token = self._issue_token(state_hash, nonce)
        return {"valid": True, "reason": "ok", "token": token}

    def sign(self, data: str) -> str:
        """
        Sign arbitrary data with the enclave key.
        Returns: hex-encoded HMAC-SHA256 signature.
        """
        sig = hmac.new(self._secret, data.encode(), hashlib.sha256).hexdigest()
        return sig

    def attest(self) -> dict:
        """
        Return an attestation report (simulated).
        In production this is a signed quote from the CPU.
        """
        report = {
            "enclave_mode": "simulation",
            "timestamp": time.time(),
            "baseline_sealed": self._baseline_hash is not None,
            "nonces_tracked": len(self._seen_nonces),
        }
        report["report_signature"] = self.sign(json.dumps(report, sort_keys=True))
        return report

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _validate_nonce(self, nonce: str) -> dict:
        now = time.time()

        # Purge expired nonces
        self._seen_nonces = {
            n: t for n, t in self._seen_nonces.items()
            if now - t < _NONCE_TTL_SECONDS
        }

        if nonce in self._seen_nonces:
            return {"valid": False, "reason": "replay attack — nonce already seen"}

        self._seen_nonces[nonce] = now
        return {"valid": True, "reason": "nonce accepted"}

    def _issue_token(self, state_hash: str, nonce: str) -> str:
        """
        Issue an attestation token binding the verified state to the nonce.
        Format: HMAC(secret, state_hash || nonce || timestamp)
        """
        payload = f"{state_hash}{nonce}{int(time.time())}".encode()
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
