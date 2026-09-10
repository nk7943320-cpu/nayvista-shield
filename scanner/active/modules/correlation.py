"""
NayVista Shield - Active Evidence & Finding Correlation Module
Correlates active assessment observations, deduplicates findings, normalizes confidence,
and ensures auditor-grade evidence attachment.
"""

from typing import Dict, Any, List
from scanner.active.base import sanitize_evidence, generate_finding_id

class CorrelationModule:
    """
    Final correlation and deduplication engine for active findings.
    """
    def correlate(self, findings: List[Dict[str, Any]], target_url: str) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            title = f.get("title", "Untitled Finding")
            endpoint = f.get("affected_component") or f.get("url") or target_url
            key = f"{title}::{endpoint}"

            if key not in deduped:
                # Ensure deterministic ID
                if not f.get("id") or not f.get("id").startswith("NS-"):
                    f["id"] = generate_finding_id("NS", f"{title}:{endpoint}")

                # Ensure confidence
                if "confidence" not in f:
                    f["confidence"] = "CONFIRMED"

                # Ensure structured evidence
                if "structured_evidence" not in f:
                    f["structured_evidence"] = {
                        "test": f.get("scanner", "Active Validation"),
                        "target": target_url,
                        "endpoint": endpoint,
                        "expected": "Secure configuration",
                        "observed": sanitize_evidence(f.get("evidence", "Observation logged")),
                        "evidence": sanitize_evidence(f.get("evidence", "")),
                        "confidence": f.get("confidence", "CONFIRMED"),
                    }
                else:
                    # Sanitize existing structured evidence
                    se = f["structured_evidence"]
                    se["observed"] = sanitize_evidence(se.get("observed", ""))
                    se["evidence"] = sanitize_evidence(se.get("evidence", ""))

                # Sanitize raw evidence
                if "evidence" in f:
                    f["evidence"] = sanitize_evidence(f["evidence"])

                deduped[key] = f
            else:
                # Merge affected URLs if present
                existing = deduped[key]
                aff_existing = set(existing.get("affected_urls", []))
                aff_new = set(f.get("affected_urls", []))
                existing["affected_urls"] = list(aff_existing | aff_new)

        # Sort findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            deduped.values(),
            key=lambda x: severity_order.get(x.get("severity", "INFO").upper(), 5)
        )
        return sorted_findings
