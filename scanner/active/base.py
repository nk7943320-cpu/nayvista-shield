"""
NayVista Shield - Base Active Security Validation Module
Provides common utilities, structured finding builders, and secret sanitization.
"""

import hashlib
import re
from typing import Dict, Any, List, Optional
from scanner.active.controller import ActiveRequestController

SECRET_PATTERNS = [
    (re.compile(r'(authorization\s*:\s*bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(authorization\s*:\s*basic\s+)([A-Za-z0-9\+\/]+=*)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key\s*[=:]\s*["\']?)([A-Za-z0-9_\-]{16,})', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret[_-]?key\s*[=:]\s*["\']?)([A-Za-z0-9_\-]{16,})', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(password\s*[=:]\s*["\']?)([^"\'\s&]+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token\s*[=:]\s*["\']?)([A-Za-z0-9_\-]{20,})', re.IGNORECASE), r'\1[REDACTED]'),
]

def sanitize_evidence(text: str) -> str:
    """Sanitizes sensitive tokens, passwords, and secret keys in evidence strings."""
    if not text:
        return text
    result = str(text)
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result

def generate_finding_id(prefix: str, key_data: str) -> str:
    """Generates a deterministic finding identifier: NS-<12hex>."""
    hasher = hashlib.sha256()
    hasher.update(key_data.encode("utf-8", errors="replace"))
    digest = hasher.hexdigest()[:12]
    return f"NS-{digest}"

class ActiveModule:
    """
    Abstract base class for all Active Security Validation modules.
    """
    name: str = "BaseModule"
    description: str = "Base active security validation module."
    stage_name: str = "general"

    def create_finding(
        self,
        title: str,
        severity: str,
        confidence: str,
        owasp: str,
        cwe: str,
        description: str,
        impact: str,
        remediation: str,
        target_url: str,
        endpoint: str,
        test_performed: str,
        expected: str,
        observed: str,
        raw_evidence: str,
        category: str = "Active Security Validation",
        references: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Builds an auditor-grade finding with structured evidence and deterministic ID.
        """
        sanitized_evidence_str = sanitize_evidence(raw_evidence)
        sanitized_observed_str = sanitize_evidence(observed)

        # Deterministic ID based on title and endpoint
        finding_id = generate_finding_id("NS", f"{title}:{endpoint}")

        structured_evidence = {
            "test": test_performed,
            "target": target_url,
            "endpoint": endpoint,
            "expected": expected,
            "observed": sanitized_observed_str,
            "evidence": sanitized_evidence_str,
            "confidence": confidence,
        }

        return {
            "id": finding_id,
            "scanner": f"ActiveValidation::{self.name}",
            "title": title,
            "severity": severity.upper(),
            "confidence": confidence.upper(),
            "owasp": owasp,
            "cwe": cwe,
            "category": category,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "url": target_url,
            "affected_component": endpoint,
            "affected_urls": [endpoint] if endpoint else [target_url],
            "evidence": f"{sanitized_observed_str} - {sanitized_evidence_str}" if sanitized_evidence_str else sanitized_observed_str,
            "structured_evidence": structured_evidence,
            "references": references or [],
            "status": "OPEN",
        }

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes active module security checks within stage budget and limits.
        """
        raise NotImplementedError
