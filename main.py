#!/usr/bin/env python3
"""
AEGIS-FLOW :: Main Entry Point
================================
CLI interface for running the AEGIS-FLOW runtime integrity monitor.

Usage:
    python main.py [OPTIONS]

Options:
    --interval FLOAT     Check interval in seconds (default: 2.0)
    --no-heal            Disable self-healing
    --log-file PATH      Write alerts to a JSONL log file
    --blockchain         Enable blockchain anchoring
    --rpc-url URL        Ethereum RPC endpoint
    --contract ADDR      AegisRegistry contract address
    --private-key HEX    Ethereum private key for signing TXs
    --duration INT       Run for N seconds then exit (0 = forever)
    --once               Run a single integrity check and exit

Author: AEGIS-FLOW Project
Version: 1.0.0
"""

import argparse
import logging
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aegis.main")


def parse_args():
    p = argparse.ArgumentParser(
        description="AEGIS-FLOW Self-Verifying Runtime Integrity Monitor"
    )
    p.add_argument("--interval", type=float, default=2.0,
                   help="Check interval in seconds (default: 2.0)")
    p.add_argument("--no-heal", action="store_true",
                   help="Disable automatic self-healing on critical violations")
    p.add_argument("--log-file", type=str, default="",
                   help="Append alerts as JSONL to this file")
    p.add_argument("--blockchain", action="store_true",
                   help="Enable Ethereum blockchain anchoring")
    p.add_argument("--rpc-url", type=str, default="",
                   help="Ethereum JSON-RPC URL (required with --blockchain)")
    p.add_argument("--contract", type=str, default="",
                   help="AegisRegistry contract address (required with --blockchain)")
    p.add_argument("--private-key", type=str, default="",
                   help="Ethereum account private key (required with --blockchain)")
    p.add_argument("--duration", type=int, default=0,
                   help="Run for N seconds then exit (0 = run forever)")
    p.add_argument("--once", action="store_true",
                   help="Run one integrity check and print result")
    p.add_argument("--verbose", action="store_true",
                   help="Enable DEBUG logging")
    return p.parse_args()


def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           AEGIS-FLOW  v1.0.0                            ║
║   Self-Verifying Runtime Integrity System               ║
║   Distributed Trust Anchoring :: Enclave-Centric        ║
╚══════════════════════════════════════════════════════════╝
""")


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    banner()

    # Import here so logging is configured first
    from core.fingerprint import compute_baseline
    from core.monitor import RuntimeMonitor, MonitorConfig
    from core.alert import file_hook

    # ── 1. Establish baseline ──────────────────────────────────────────
    logger.info("Computing baseline state fingerprint…")
    baseline = compute_baseline()
    logger.info("Baseline established: hash=%s", baseline["state_hash"][:32])

    # ── 2. Build alert hooks ───────────────────────────────────────────
    hooks = []
    if args.log_file:
        hooks.append(file_hook(args.log_file))
        logger.info("Alert log: %s", args.log_file)

    # ── 3. Configure monitor ───────────────────────────────────────────
    config = MonitorConfig(
        interval_seconds=args.interval,
        auto_heal=not args.no_heal,
        alert_hooks=hooks,
        blockchain_enabled=args.blockchain,
        blockchain_rpc_url=args.rpc_url,
        blockchain_contract=args.contract,
        blockchain_private_key=args.private_key,
    )

    if args.blockchain and not (args.rpc_url and args.contract and args.private_key):
        logger.error(
            "Blockchain mode requires --rpc-url, --contract, and --private-key"
        )
        sys.exit(1)

    monitor = RuntimeMonitor(baseline=baseline, config=config)

    # ── 4. Run ────────────────────────────────────────────────────────
    if args.once:
        logger.info("Running single integrity check…")
        result = monitor.run_once()
        import json
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["match"] else 1)

    monitor.start()
    logger.info("Monitor running. Press Ctrl+C to stop.")

    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down…")
    finally:
        monitor.stop()
        status = monitor.status()
        print(f"\n── Session Summary ──────────────────────────────────")
        print(f"   Checks     : {status['checks_performed']}")
        print(f"   Violations : {status['violations_detected']}")
        print(f"────────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
