"""
SentinelScan - Scanner CLI Entrypoint
Can be executed from terminal or invoked by Node.js backend subprocess.
Usage:
  python scanner_cli.py --target https://example.com [--allow-local]
"""

import sys
import os
import json
import argparse
import asyncio

# Ensure parent directory of scanner is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from scanner.orchestrator import ScanOrchestrator

def main():
    parser = argparse.ArgumentParser(description="NayVista Shield CLI Security Assessment Runner")
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--allow-local", action="store_true", help="Permit testing local mock endpoints (for testing)")
    parser.add_argument("--mode", choices=["defensive", "safe", "active", "authorized"], default="defensive", help="Assessment mode")
    parser.add_argument("--authorized", action="store_true", help="Confirm explicit authorization for active assessment")
    parser.add_argument("--modules", nargs="*", help="Optional module selection")
    args = parser.parse_args()

    mode_val = "ACTIVE / AUTHORIZED TESTING" if args.mode in ("active", "authorized") else "DEFENSIVE / SAFE"
    orchestrator = ScanOrchestrator(
        target_url=args.target,
        allow_local=args.allow_local,
        mode=mode_val,
        authorized=args.authorized or (mode_val == "DEFENSIVE / SAFE"),
        selected_modules=args.modules,
    )
    try:
        result = asyncio.run(orchestrator.run_scan())
        # Print final result delimiter
        sys.stdout.write("\n===NAYVISTA_RESULT===\n")
        sys.stdout.write(json.dumps(result, indent=2))
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        error_event = {
            "type": "error",
            "error": str(e),
        }
        sys.stderr.write(json.dumps(error_event) + "\n")
        sys.stderr.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
