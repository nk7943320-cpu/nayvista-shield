"""
SentinelScan - Orchestrator Wrapper
Delegates to scanner.engine.ScannerEngine while supporting JSON-lines progress stdout.
"""

import sys
import json
import time
from typing import Dict, Any, Optional
from scanner.engine import ScannerEngine, ProgressCallback

def emit_progress(phase: str, message: str, step: int, total_steps: int = 14, stats: Optional[Dict[str, Any]] = None):
    event = {
        "type": "progress",
        "phase": phase,
        "message": message,
        "step": step,
        "total_steps": total_steps,
        "stats": stats or {},
        "timestamp": time.time(),
    }
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()

class ScanOrchestrator(ScannerEngine):
    def __init__(
        self,
        target_url: str,
        allow_local: bool = False,
        on_progress: Optional[ProgressCallback] = None,
        mode: str = "DEFENSIVE / SAFE",
        authorized: bool = False,
        scope_manifest: Optional[Dict[str, Any]] = None,
        selected_modules: Optional[List[str]] = None,
        cancel_event: Optional[Any] = None,
    ):
        super().__init__(
            target_url=target_url,
            allow_local=allow_local,
            on_progress=on_progress or emit_progress,
            mode=mode,
            authorized=authorized,
            scope_manifest=scope_manifest,
            selected_modules=selected_modules,
            cancel_event=cancel_event,
        )

    async def run_scan(self) -> Dict[str, Any]:
        return await self.scan_async()
