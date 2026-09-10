"""
SentinelScan - HTTP Methods Module
Safely sends an OPTIONS request to inspect allowed HTTP verbs.
Flags dangerous methods like TRACE (Cross-Site Tracing) or unusual verbs.
"""

from typing import List, Dict, Any
import httpx
from scanner.scope import TargetScope
from scanner.findings import create_finding

class HTTPMethodsScanner:
    def scan(self, scope: TargetScope) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        target_url = f"{scope.scheme}://{scope.hostname}:{scope.port}/"

        try:
            with httpx.Client(verify=not scope.allow_local, timeout=6.0) as client:
                resp = client.options(target_url, headers={"User-Agent": "SentinelScan-Security-Auditor/1.0"})
                allow_header = resp.headers.get("allow") or resp.headers.get("public") or ""

                if allow_header:
                    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

                    # Check for TRACE or TRACK
                    if "TRACE" in methods or "TRACK" in methods:
                        findings.append(create_finding(
                            scanner="methods",
                            title="Dangerous HTTP Method Enabled: TRACE/TRACK",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="Security Misconfiguration",
                            owasp_key="SECURITY_MISCONFIGURATION",
                            url=target_url,
                            evidence=f"Allow header: '{allow_header}'",
                            description="The web server permits TRACE or TRACK methods, which reflect the client's request including headers.",
                            impact="May allow attackers to bypass HttpOnly cookie protections via Cross-Site Tracing (XST).",
                            remediation="Disable TRACE and TRACK in the web server configuration (e.g. TraceEnable off in Apache)."
                        ))

                    # Check for DEBUG method
                    if "DEBUG" in methods:
                        findings.append(create_finding(
                            scanner="methods",
                            title="Unusual HTTP Method Enabled: DEBUG",
                            severity="LOW",
                            confidence="MEDIUM",
                            category="Security Misconfiguration",
                            owasp_key="SECURITY_MISCONFIGURATION",
                            url=target_url,
                            evidence=f"Allow header contains DEBUG method: '{allow_header}'",
                            description="The server advertises support for the DEBUG HTTP method, often associated with test environments.",
                            impact="May disclose internal debugging endpoints or diagnostic routines.",
                            remediation="Disable non-standard debugging methods in production."
                        ))

                    # Informational inventory of methods
                    write_verbs = [v for v in ("PUT", "DELETE") if v in methods]
                    if write_verbs:
                        findings.append(create_finding(
                            scanner="methods",
                            title=f"HTTP Write Methods Advertised ({', '.join(write_verbs)})",
                            severity="INFO",
                            confidence="HIGH",
                            category="Security Misconfiguration",
                            owasp_key="SECURITY_MISCONFIGURATION",
                            url=target_url,
                            evidence=f"Server advertises methods: '{allow_header}'",
                            description=f"The server allows {', '.join(write_verbs)} on the base URL.",
                            impact="Ensure proper authorization checks guard these endpoints if state modification is permitted.",
                            remediation="Verify that write methods require strict authentication and authorization."
                        ))

        except Exception:
            pass

        return findings
