"""
SentinelScan - Normalizer Backward Compatibility Wrapper
Re-exports from scanner.findings.
"""

from scanner.findings import (
    SEVERITY_LEVELS,
    CONFIDENCE_LEVELS,
    OWASP_MAPPINGS,
    sanitize_evidence,
    create_finding,
    deduplicate_findings,
)

__all__ = [
    "SEVERITY_LEVELS",
    "CONFIDENCE_LEVELS",
    "OWASP_MAPPINGS",
    "sanitize_evidence",
    "create_finding",
    "deduplicate_findings",
]
