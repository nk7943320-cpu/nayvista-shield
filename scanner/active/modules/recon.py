"""
NayVista Shield - Active Reconnaissance & Discovery Module
Validates HTTP OPTIONS capabilities, robots.txt disclosures, and security.txt compliance.
"""

from typing import Dict, Any, List
from urllib.parse import urljoin
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class ReconDiscoveryModule(ActiveModule):
    name = "ReconDiscovery"
    description = "Active reconnaissance for HTTP methods, robots.txt, and security.txt"
    stage_name = "Reconnaissance"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Recon & Discovery")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        # 1. Probe OPTIONS on root
        options_resp = await controller.request("OPTIONS", target)
        if options_resp and options_resp.is_success:
            allow_header = options_resp.headers.get("allow", "")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                dangerous_methods = [m for m in methods if m in ("TRACE", "TRACK", "DEBUG")]
                if dangerous_methods:
                    findings.append(self.create_finding(
                        title="Dangerous HTTP Methods Enabled (OPTIONS)",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-16",
                        description=f"Target advertises support for sensitive or debug HTTP methods: {', '.join(dangerous_methods)} via the Allow header.",
                        impact="Attackers can exploit TRACE/TRACK for Cross-Site Tracing (XST) to bypass HttpOnly cookie flags.",
                        remediation="Disable TRACE, TRACK, and arbitrary debugging HTTP methods on the web server.",
                        target_url=target,
                        endpoint=target,
                        test_performed="HTTP OPTIONS request on root origin",
                        expected="Only standard safe methods (GET, HEAD, POST, OPTIONS)",
                        observed=f"Allow: {allow_header}",
                        raw_evidence=f"Status: {options_resp.status_code}, Allow: {allow_header}",
                    ))

        # 2. Check /robots.txt for sensitive path disclosure
        robots_url = urljoin(target, "/robots.txt")
        robots_resp = await controller.request("GET", robots_url)
        if robots_resp and robots_resp.status_code == 200 and "disallow" in robots_resp.text.lower():
            lines = robots_resp.text.splitlines()
            disallowed = []
            sensitive_keywords = ["admin", "secret", "private", "backup", "internal", "config", "staging", "dev"]
            exposed_sensitive = []
            for line in lines:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[0].strip().lower() == "disallow":
                    path = parts[1].strip()
                    if path and path != "/":
                        disallowed.append(path)
                        if any(k in path.lower() for k in sensitive_keywords):
                            exposed_sensitive.append(path)

            if exposed_sensitive:
                findings.append(self.create_finding(
                    title="Sensitive Directory Exposure in robots.txt",
                    severity="LOW",
                    confidence="CONFIRMED",
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-200",
                    description=f"The robots.txt file exposes administrative or restricted directory locations: {', '.join(exposed_sensitive[:5])}",
                    impact="Search engine exclusion rules can be harvested by adversaries to identify hidden internal or administrative attack surfaces.",
                    remediation="Do not rely on robots.txt for access control. Protect sensitive endpoints with proper authentication and authorization.",
                    target_url=target,
                    endpoint=robots_url,
                    test_performed="GET /robots.txt retrieval and path analysis",
                    expected="Robots.txt should not enumerate confidential paths",
                    observed=f"Disallowed paths identified: {', '.join(exposed_sensitive[:5])}",
                    raw_evidence=f"Disallowed matches: {exposed_sensitive[:5]}",
                ))

            # Register discovered endpoints into context for subsequent modules
            discovered = context.setdefault("discovered_endpoints", set())
            for d in disallowed[:10]:
                discovered.add(urljoin(target, d))

        # 3. Check /.well-known/security.txt compliance (RFC 9116)
        sec_url = urljoin(target, "/.well-known/security.txt")
        sec_resp = await controller.request("GET", sec_url)
        if not sec_resp or sec_resp.status_code != 200 or "contact:" not in sec_resp.text.lower():
            findings.append(self.create_finding(
                title="Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                severity="INFO",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1059",
                description="The target domain does not publish a security.txt file at /.well-known/security.txt conforming to RFC 9116.",
                impact="Security researchers and auditors lack a standardized, verified channel to report responsible vulnerability disclosures.",
                remediation="Publish a valid security.txt file at /.well-known/security.txt containing Contact, Canonical, and Policy directives.",
                target_url=target,
                endpoint=sec_url,
                test_performed="GET /.well-known/security.txt probe",
                expected="HTTP 200 with Contact directive conforming to RFC 9116",
                observed=f"HTTP status: {sec_resp.status_code if sec_resp else 'No Response'}",
                raw_evidence=f"Status: {sec_resp.status_code if sec_resp else 'None'}",
            ))

        return findings
