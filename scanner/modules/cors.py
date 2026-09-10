"""
SentinelScan - CORS Security Module
Analyzes Cross-Origin Resource Sharing (CORS) configurations:
- Wildcard origin (*) with credentials allowed.
- Arbitrary origin reflection.
- 'null' origin allowed.
"""

from typing import List, Dict, Any
import httpx
from scanner.crawler import CrawledPage
from scanner.scope import TargetScope
from scanner.findings import create_finding

PROBE_ORIGIN = "https://sentinelscan-audit-origin.example"

class CORSScanner:
    def scan(self, scope: TargetScope, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not pages:
            return findings

        # Analyze passive headers from crawled pages
        for page in pages[:3]:
            headers = {k.lower(): v for k, v in page.headers.items()}
            acao = headers.get("access-control-allow-origin")
            acac = headers.get("access-control-allow-credentials", "").lower() == "true"

            if acao:
                if acao.strip() == "*" and acac:
                    findings.append(create_finding(
                        scanner="cors",
                        title="Dangerous CORS Configuration: Wildcard Origin with Credentials",
                        severity="HIGH",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                        description="The server allows any external origin to read responses while permitting credentialed cross-origin requests.",
                        impact="Third-party malicious websites could make authenticated requests on behalf of users and exfiltrate sensitive data.",
                        remediation="Do not combine wildcard '*' with 'Access-Control-Allow-Credentials: true'. Specify trusted explicit origins."
                    ))
                elif acao.strip().lower() == "null":
                    findings.append(create_finding(
                        scanner="cors",
                        title="Insecure CORS Policy Allowing 'null' Origin",
                        severity="MEDIUM",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence="Access-Control-Allow-Origin: null",
                        description="The CORS policy trusts 'null' as a valid origin. Sandboxed iframes and local file URIs generate a null origin.",
                        impact="Malicious sandboxed iframes can bypass same-origin policy protections and access server responses.",
                        remediation="Avoid permitting 'null' in Access-Control-Allow-Origin. Whitelist explicit, trusted origin domains."
                    ))

        # Safe active origin reflection probe on root
        target_url = pages[0].url
        try:
            with httpx.Client(verify=not scope.allow_local, timeout=5.0) as client:
                probe_resp = client.get(
                    target_url,
                    headers={"Origin": PROBE_ORIGIN, "User-Agent": "SentinelScan-Security-Auditor/1.0"}
                )
                p_headers = {k.lower(): v for k, v in probe_resp.headers.items()}
                p_acao = p_headers.get("access-control-allow-origin", "")
                p_acac = p_headers.get("access-control-allow-credentials", "").lower() == "true"

                if p_acao.strip() == PROBE_ORIGIN:
                    severity = "HIGH" if p_acac else "MEDIUM"
                    findings.append(create_finding(
                        scanner="cors",
                        title="CORS Origin Reflection Detected",
                        severity=severity,
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=target_url,
                        evidence=f"Request Origin '{PROBE_ORIGIN}' was dynamically reflected in Access-Control-Allow-Origin (Credentials: {p_acac})",
                        description="The server dynamically echoes arbitrary request Origin headers without validating them against a strict whitelist.",
                        impact="Any malicious site visited by an authenticated user can read sensitive cross-origin data.",
                        remediation="Validate Origin headers against a strict whitelist of trusted domain names rather than reflecting arbitrary inputs."
                    ))
        except Exception:
            pass

        return findings
