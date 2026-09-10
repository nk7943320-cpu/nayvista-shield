"""
NayVista Shield - Findings Model, Sanitization & Deduplication
Defines canonical finding structures with deterministic IDs, CWE mappings,
lifecycle states, and strict secret redaction.
"""

import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_LEVELS = ["LOW", "MEDIUM", "HIGH"]
FINDING_STATUSES = ["OPEN", "RESOLVED", "RECURRED", "ACCEPTED_RISK"]

OWASP_MAPPINGS = {
    "BROKEN_ACCESS_CONTROL": "A01:2021-Broken Access Control",
    "CRYPTOGRAPHIC_FAILURES": "A02:2021-Cryptographic Failures",
    "INJECTION": "A03:2021-Injection",
    "INSECURE_DESIGN": "A04:2021-Insecure Design",
    "SECURITY_MISCONFIGURATION": "A05:2021-Security Misconfiguration",
    "VULNERABLE_COMPONENTS": "A06:2021-Vulnerable and Outdated Components",
    "AUTH_FAILURES": "A07:2021-Identification and Authentication Failures",
    "INTEGRITY_FAILURES": "A08:2021-Software and Data Integrity Failures",
    "LOGGING_FAILURES": "A09:2021-Security Logging and Monitoring Failures",
    "SSRF": "A10:2021-Server-Side Request Forgery",
}

DEFAULT_CWE_LOOKUP = [
    ("content security policy", "CWE-693"),
    ("strict transport security", "CWE-319"),
    ("x-content-type-options", "CWE-693"),
    ("x-frame-options", "CWE-1021"),
    ("clickjacking", "CWE-1021"),
    ("referrer-policy", "CWE-116"),
    ("permissions-policy", "CWE-693"),
    ("secure flag", "CWE-614"),
    ("httponly", "CWE-1004"),
    ("samesite", "CWE-1275"),
    ("cookie", "CWE-614"),
    ("tls certificate verification failed", "CWE-295"),
    ("certificate", "CWE-295"),
    ("tls", "CWE-326"),
    ("ssl", "CWE-326"),
    ("cors", "CWE-942"),
    ("information disclosure", "CWE-552"),
    ("directory listing", "CWE-548"),
    ("git repository", "CWE-552"),
    ("backup", "CWE-530"),
    ("private key", "CWE-552"),
    ("environment file", "CWE-552"),
    ("dangerous http method", "CWE-650"),
    ("trace method", "CWE-693"),
    ("open redirect", "CWE-601"),
    ("server banner", "CWE-200"),
    ("x-powered-by", "CWE-200"),
    ("injection", "CWE-79"),
    ("rate limiting", "CWE-799"),
    ("waf", "CWE-693"),
    ("server error", "CWE-754"),
]

DEFAULT_REFERENCES = {
    "CWE-693": [
        "https://cwe.mitre.org/data/definitions/693.html",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "CWE-319": [
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    "CWE-1021": [
        "https://cwe.mitre.org/data/definitions/1021.html",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "CWE-614": [
        "https://cwe.mitre.org/data/definitions/614.html",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "CWE-1004": [
        "https://cwe.mitre.org/data/definitions/1004.html",
    ],
    "CWE-1275": [
        "https://cwe.mitre.org/data/definitions/1275.html",
    ],
    "CWE-295": [
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    "CWE-326": [
        "https://cwe.mitre.org/data/definitions/326.html",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ],
    "CWE-942": [
        "https://cwe.mitre.org/data/definitions/942.html",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
    "CWE-552": [
        "https://cwe.mitre.org/data/definitions/552.html",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
    "CWE-548": [
        "https://cwe.mitre.org/data/definitions/548.html",
    ],
    "CWE-601": [
        "https://cwe.mitre.org/data/definitions/601.html",
    ],
    "CWE-650": [
        "https://cwe.mitre.org/data/definitions/650.html",
    ],
    "CWE-200": [
        "https://cwe.mitre.org/data/definitions/200.html",
    ],
    "CWE-79": [
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ],
}

# Regex for redacting potential secrets in evidence, logs, and findings
SECRET_PATTERNS = [
    # Passwords, secrets, tokens, API keys in query, json, or text
    (re.compile(r'(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*["\']?([^"\'\s&]{4,})["\']?'), r'\1=[REDACTED]'),
    # Set-Cookie headers (strictly redact cookie values while keeping flags)
    (re.compile(r'(?i)(Set-Cookie:\s*[^=]+)=([^;\r\n]+)'), r'\1=[REDACTED]'),
    # Cookie request headers
    (re.compile(r'(?i)(Cookie:\s*[^=]+)=([^;\r\n]+)'), r'\1=[REDACTED]'),
    # Authorization headers (Bearer, Basic, Token)
    (re.compile(r'(?i)(Authorization:\s*(?:Bearer|Basic|Token)\s+)([A-Za-z0-9_\-\.\+/=]+)'), r'\1[REDACTED]'),
    # AWS Access Key ID (AKIA...)
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), r'[REDACTED]'),
    # GitHub Personal Access Tokens
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b'), r'[REDACTED]'),
    # Slack tokens
    (re.compile(r'\b(xox[baprs]-[A-Za-z0-9\-]{20,72})\b'), r'[REDACTED]'),
    # JWT tokens
    (re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'), r'[REDACTED]'),
    # Private Key blocks
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]+-----END [A-Z ]*PRIVATE KEY-----', re.DOTALL), r'[REDACTED]'),
]

def sanitize_evidence(evidence: str) -> str:
    """Removes passwords, secret tokens, and raw cookie values from evidence strings."""
    if not evidence:
        return ""
    sanitized = str(evidence)
    for pattern, repl in SECRET_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    # Truncate overly long evidence to 1000 chars to avoid memory bloat
    if len(sanitized) > 1000:
        sanitized = sanitized[:997] + "..."
    return sanitized

def generate_finding_id(url: str, category: str, title: str, component: str = "") -> str:
    """
    Generates a deterministic finding ID: NS-<12hex>
    Ensures identical findings across scans share the same ID.
    Never includes volatile evidence, timestamps, or transient counters.
    """
    parsed = urlparse(url)
    host = (parsed.netloc or url).lower().strip()
    cat = (category or "").lower().strip()
    tit = (title or "").lower().strip()
    comp = (component or "").lower().strip()
    seed = f"{host}::{cat}::{tit}::{comp}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"NS-{digest}"

def create_finding(
    scanner: str,
    title: str,
    severity: str,
    confidence: str,
    category: str,
    owasp_key: str,
    url: str,
    evidence: str,
    description: str,
    impact: str,
    remediation: str,
    finding_id: Optional[str] = None,
    cwe: Optional[str] = None,
    affected_component: Optional[str] = None,
    references: Optional[List[str]] = None,
    status: str = "OPEN",
    first_seen: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs a validated canonical finding object."""
    sev = severity.upper()
    if sev not in SEVERITY_LEVELS:
        sev = "INFO"

    conf = confidence.upper()
    if conf not in CONFIDENCE_LEVELS:
        conf = "MEDIUM"

    owasp = OWASP_MAPPINGS.get(owasp_key, owasp_key or "A05:2021-Security Misconfiguration")

    # Determine affected component
    comp = (affected_component or "").strip()
    if not comp:
        comp = scanner.strip()

    # Determine CWE
    cwe_val = cwe
    if not cwe_val:
        title_lower = title.lower()
        for pattern, mapped_cwe in DEFAULT_CWE_LOOKUP:
            if pattern in title_lower:
                cwe_val = mapped_cwe
                break
        if not cwe_val:
            cwe_val = "CWE-693"

    # Determine References
    refs = list(references) if references else []
    if not refs:
        refs = DEFAULT_REFERENCES.get(cwe_val, [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/693.html"
        ])

    # Determine Deterministic ID
    fid = finding_id or generate_finding_id(url, category, title, comp)

    # Determine Status
    status_val = status.upper() if status else "OPEN"
    if status_val not in FINDING_STATUSES:
        status_val = "OPEN"

    first_seen_ts = first_seen or datetime.now(timezone.utc).isoformat()

    return {
        "id": fid,
        "title": title.strip(),
        "severity": sev,
        "confidence": conf,
        "status": status_val,
        "category": category.strip(),
        "owasp": owasp,
        "cwe": cwe_val,
        "url": url.strip(),
        "affected_component": comp,
        "description": description.strip(),
        "evidence": sanitize_evidence(evidence),
        "impact": impact.strip(),
        "remediation": remediation.strip(),
        "references": refs,
        "first_seen": first_seen_ts,
        "firstSeen": first_seen_ts,
        "scan_id": scan_id or "",
        "scanId": scan_id or "",
        "scanner": scanner,
        "affected_urls": [url.strip()],
    }

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups findings by deterministic ID so duplicate issues across multiple
    crawled pages are consolidated while preserving all affected URLs.
    """
    deduped: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        key = f.get("id") or f"{f.get('scanner', '')}::{f.get('title', '')}::{f.get('category', '')}"
        if key not in deduped:
            finding_copy = dict(f)
            curr_url = f.get("url", "")
            finding_copy["affected_urls"] = [curr_url] if curr_url else []
            deduped[key] = finding_copy
        else:
            existing = deduped[key]
            curr_url = f.get("url", "")
            if curr_url and curr_url not in existing["affected_urls"]:
                existing["affected_urls"].append(curr_url)
            # Retain the highest severity if different
            curr_sev_idx = SEVERITY_LEVELS.index(f.get("severity", "INFO"))
            exist_sev_idx = SEVERITY_LEVELS.index(existing.get("severity", "INFO"))
            if curr_sev_idx > exist_sev_idx:
                existing["severity"] = f["severity"]

    return list(deduped.values())

