"""
AEGIS-FLOW :: State Fingerprinting Engine
==========================================
Captures a cryptographic snapshot of the current runtime environment:
  - Process memory
  - CPU usage
  - Open file descriptors
  - Loaded modules
  - Control-flow nonce (contextual)

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import hashlib
import json
import os
import sys
import time
import psutil
import platform
import hmac
import secrets


def _get_process_info() -> dict:
    """Capture current process metrics."""
    proc = psutil.Process(os.getpid())
    try:
        fds = proc.num_fds() if hasattr(proc, "num_fds") else -1
    except Exception:
        fds = -1

    return {
        "pid": proc.pid,
        "memory_rss": proc.memory_info().rss,
        "memory_vms": proc.memory_info().vms,
        "cpu_percent": proc.cpu_percent(interval=0.1),
        "num_threads": proc.num_threads(),
        "num_fds": fds,
        "status": proc.status(),
    }


def _get_module_fingerprint() -> str:
    """Hash the set of currently loaded Python modules."""
    module_names = sorted(sys.modules.keys())
    raw = "|".join(module_names).encode()
    return hashlib.sha256(raw).hexdigest()


def _get_env_fingerprint() -> str:
    """Hash a subset of environment variables (non-sensitive keys only)."""
    safe_keys = ["PATH", "LANG", "TERM", "USER", "HOME", "SHELL", "OS"]
    env_data = {k: os.environ.get(k, "") for k in safe_keys}
    raw = json.dumps(env_data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _get_platform_info() -> dict:
    """Gather platform/OS-level info."""
    return {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }


def generate_nonce() -> str:
    """Generate a cryptographically secure contextual nonce."""
    return secrets.token_hex(32)


def compute_state_fingerprint(nonce: str) -> dict:
    """
    Compute a full state fingerprint.

    Returns a dict containing:
      - component hashes
      - combined state hash
      - timestamp
      - nonce used
    """
    timestamp = time.time()
    process_info = _get_process_info()
    module_fp = _get_module_fingerprint()
    env_fp = _get_env_fingerprint()
    platform_info = _get_platform_info()

    # Build the state blob
    state_blob = {
        "timestamp": timestamp,
        "nonce": nonce,
        "process": process_info,
        "modules_hash": module_fp,
        "env_hash": env_fp,
        "platform": platform_info,
    }

    # Compute combined hash
    raw = json.dumps(state_blob, sort_keys=True).encode()
    state_hash = hashlib.sha256(raw).hexdigest()

    return {
        "state_hash": state_hash,
        "timestamp": timestamp,
        "nonce": nonce,
        "components": {
            "process": process_info,
            "modules_hash": module_fp,
            "env_hash": env_fp,
            "platform": platform_info,
        },
    }


def compute_baseline() -> dict:
    """
    Compute and return the baseline state fingerprint.
    Call this once at startup to establish the trusted state.
    """
    nonce = generate_nonce()
    baseline = compute_state_fingerprint(nonce)
    baseline["baseline"] = True
    return baseline


def compare_states(baseline: dict, current: dict) -> dict:
    """
    Compare a current fingerprint against a baseline.

    Returns a result dict with:
      - match (bool)
      - drift (list of changed fields)
    """
    drift = []

    b_proc = baseline["components"]["process"]
    c_proc = current["components"]["process"]

    # Check memory drift (allow ±5MB tolerance)
    rss_delta = abs(c_proc["memory_rss"] - b_proc["memory_rss"])
    if rss_delta > 5 * 1024 * 1024:
        drift.append({
            "field": "memory_rss",
            "baseline": b_proc["memory_rss"],
            "current": c_proc["memory_rss"],
            "delta": rss_delta,
        })

    # Check thread count
    if c_proc["num_threads"] != b_proc["num_threads"]:
        drift.append({
            "field": "num_threads",
            "baseline": b_proc["num_threads"],
            "current": c_proc["num_threads"],
        })

    # Module fingerprint
    if current["components"]["modules_hash"] != baseline["components"]["modules_hash"]:
        drift.append({
            "field": "modules_hash",
            "baseline": baseline["components"]["modules_hash"],
            "current": current["components"]["modules_hash"],
        })

    # Env fingerprint
    if current["components"]["env_hash"] != baseline["components"]["env_hash"]:
        drift.append({
            "field": "env_hash",
            "baseline": baseline["components"]["env_hash"],
            "current": current["components"]["env_hash"],
        })

    # Platform
    if current["components"]["platform"] != baseline["components"]["platform"]:
        drift.append({
            "field": "platform",
            "baseline": baseline["components"]["platform"],
            "current": current["components"]["platform"],
        })

    return {
        "match": len(drift) == 0,
        "drift": drift,
        "baseline_hash": baseline["state_hash"],
        "current_hash": current["state_hash"],
    }
