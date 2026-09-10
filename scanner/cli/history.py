"""
NayVista Shield - CLI Local Scan History Storage
Maintains persistent local assessment history across CLI sessions.
Stores records in ~/.nayvista-shield/history.json with fallback to local workspace.
"""

import os
import json
import time
import uuid
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

def _get_history_file_path() -> str:
    """Returns the persistent history file path, creating directory if necessary."""
    try:
        home = os.path.expanduser("~")
        config_dir = os.path.join(home, ".nayvista-shield")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "history.json")
    except Exception:
        # Fallback to local directory
        return os.path.abspath(".nayvista_history.json")

def load_history() -> List[Dict[str, Any]]:
    """Loads all saved scan records, ordered from newest to oldest."""
    path = _get_history_file_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return sorted(data, key=lambda s: s.get("timestamp", 0), reverse=True)
            return []
    except Exception:
        return []

def save_scan(result: Dict[str, Any]) -> str:
    """
    Saves a completed scan result to the persistent history store.
    Returns the scan ID.
    """
    history = load_history()
    scan_id = result.get("id") or str(uuid.uuid4())

    scoring = result.get("scoring", {})
    target = result.get("target") or result.get("normalized_target", "")
    parsed = urlparse(target)
    hostname = result.get("hostname") or parsed.hostname or "unknown"
    port = result.get("port") or parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = result.get("scheme") or parsed.scheme or "https"

    record = {
        "id": scan_id,
        "target": target,
        "normalized_target": result.get("normalized_target", target),
        "hostname": hostname,
        "port": port,
        "scheme": scheme,
        "origin": f"{hostname}:{port}",
        "timestamp": time.time(),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "score": scoring.get("score", 100),
        "grade": scoring.get("grade", "A"),
        "risk_level": scoring.get("risk_level", "LOW"),
        "posture": result.get("posture", "ASSESSED"),
        "duration_seconds": result.get("duration_seconds", 0.0),
        "pages_scanned": result.get("pages_scanned", 0),
        "findings_count": len(result.get("findings", [])),
        "mode": result.get("mode", "DEFENSIVE / SAFE"),
        "resolved_ip": result.get("resolved_ip", "N/A"),
        "dns": result.get("dns", {}),
        "network_exposure": result.get("network_exposure", []),
        "findings": result.get("findings", []),
        "inventory": result.get("inventory", {}),
        "technologies": result.get("technologies", {}),
    }

    # Prepend newest scan
    history.insert(0, record)

    # Keep up to 200 previous scans
    if len(history) > 200:
        history = history[:200]

    path = _get_history_file_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

    return scan_id

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a specific scan by ID."""
    history = load_history()
    for s in history:
        if s.get("id") == scan_id:
            return s
    return None

def get_targets_history() -> Dict[str, List[Dict[str, Any]]]:
    """
    Groups historical scans by canonical target origin (e.g. example.com:443).
    Returns a dictionary mapping origin -> list of scans chronologically.
    """
    history = load_history()
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for s in history:
        origin = s.get("origin") or f"{s.get('hostname', 'unknown')}:{s.get('port', 443)}"
        if origin not in groups:
            groups[origin] = []
        groups[origin].append(s)

    # Sort each group chronologically (newest first)
    for origin in groups:
        groups[origin] = sorted(groups[origin], key=lambda x: x.get("timestamp", 0), reverse=True)

    return groups

def delete_scan(scan_id: str) -> bool:
    """Deletes a scan record by ID."""
    history = load_history()
    initial_len = len(history)
    history = [s for s in history if s.get("id") != scan_id]
    if len(history) < initial_len:
        path = _get_history_file_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            return True
        except Exception:
            return False
    return False
