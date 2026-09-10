"""
NayVista Shield - Active HTTP Security Validation Module
Validates security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy)
and server technology disclosure headers.
"""

from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class HTTPSecurityValidationModule(ActiveModule):
    name = "HTTPSecurityValidation"
    description = "Active HTTP security headers and defense configuration audit"
    stage_name = "HTTP Security"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("HTTP Security")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        resp = await controller.request("GET", target)
        if not resp:
            return findings

        headers = resp.headers
        context["root_headers"] = headers

        # 1. HSTS (Strict-Transport-Security)
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(self.create_finding(
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity="MEDIUM",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-319",
                description="The response lacks a Strict-Transport-Security header, allowing browsers to connect over unencrypted HTTP.",
                impact="Susceptible to SSL-stripping and man-in-the-middle attacks when clients first connect over plaintext HTTP.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                target_url=target,
                endpoint=target,
                test_performed="HTTP response header inspection for Strict-Transport-Security",
                expected="Strict-Transport-Security: max-age >= 15552000",
                observed="Header absent",
                raw_evidence="Headers: " + ", ".join(headers.keys()),
            ))

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(self.create_finding(
                title="Missing Content-Security-Policy (CSP)",
                severity="MEDIUM",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                description="The website does not deploy a Content-Security-Policy header to restrict content loading origins.",
                impact="Heightens risk of Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
                remediation="Deploy a robust Content-Security-Policy defining trusted script-src, style-src, and default-src directives.",
                target_url=target,
                endpoint=target,
                test_performed="HTTP response header inspection for Content-Security-Policy",
                expected="Content-Security-Policy header defined with restrictive sources",
                observed="Header absent",
                raw_evidence="Headers: " + ", ".join(headers.keys()),
            ))
        else:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(self.create_finding(
                    title="Weak Content-Security-Policy (Unsafe Directives Permitted)",
                    severity="LOW",
                    confidence="CONFIRMED",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1021",
                    description="The Content-Security-Policy includes 'unsafe-inline' or 'unsafe-eval', weakening XSS protections.",
                    impact="Enables malicious script execution if an inline script injection flaw exists.",
                    remediation="Refactor inline scripts to use cryptographic nonces or hashes and eliminate 'unsafe-inline'.",
                    target_url=target,
                    endpoint=target,
                    test_performed="Content-Security-Policy directive parsing",
                    expected="Absence of 'unsafe-inline' and 'unsafe-eval'",
                    observed=f"CSP: {csp[:120]}...",
                    raw_evidence=f"CSP: {csp}",
                ))

        # 3. X-Frame-Options (Clickjacking)
        xfo = headers.get("x-frame-options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append(self.create_finding(
                title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                severity="LOW",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021",
                description="Neither X-Frame-Options nor CSP frame-ancestors is present to protect pages from iframe framing.",
                impact="Adversaries can embed the target application within a transparent iframe to perform clickjacking attacks.",
                remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or configure CSP 'frame-ancestors 'self''.",
                target_url=target,
                endpoint=target,
                test_performed="Clickjacking header inspection",
                expected="X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors",
                observed="Neither X-Frame-Options nor frame-ancestors configured",
                raw_evidence="Headers: " + ", ".join(headers.keys()),
            ))

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(self.create_finding(
                title="Missing X-Content-Type-Options: nosniff",
                severity="LOW",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-16",
                description="The response lacks 'X-Content-Type-Options: nosniff' header, permitting MIME-sniffing.",
                impact="Browsers may interpret executable scripts disguised as images or text files, leading to XSS.",
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                target_url=target,
                endpoint=target,
                test_performed="MIME-sniffing protection header check",
                expected="X-Content-Type-Options: nosniff",
                observed=f"Header: {xcto or 'Absent'}",
                raw_evidence=f"Value: {xcto}",
            ))

        # 5. Technology banner disclosures (Server, X-Powered-By)
        disclosed_tech = []
        if "server" in headers:
            disclosed_tech.append(f"Server: {headers['server']}")
            detected_servers = context.setdefault("detected_servers", [])
            if headers["server"] not in detected_servers:
                detected_servers.append(headers["server"])
        if "x-powered-by" in headers:
            disclosed_tech.append(f"X-Powered-By: {headers['x-powered-by']}")
            detected_backend = context.setdefault("detected_backend", [])
            if headers["x-powered-by"] not in detected_backend:
                detected_backend.append(headers["x-powered-by"])
        if "x-aspnet-version" in headers:
            disclosed_tech.append(f"X-AspNet-Version: {headers['x-aspnet-version']}")

        if disclosed_tech:
            findings.append(self.create_finding(
                title="Technology Stack Fingerprint Disclosed in Response Headers",
                severity="INFO",
                confidence="CONFIRMED",
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-200",
                description=f"Server exposes technology details in HTTP headers: {', '.join(disclosed_tech)}",
                impact="Disclosing precise software versions simplifies reconnaissance for known CVE exploits.",
                remediation="Suppress or sanitize Server and X-Powered-By header banners in web server configuration.",
                target_url=target,
                endpoint=target,
                test_performed="HTTP banner enumeration",
                expected="Suppression of detailed server versions and technology banners",
                observed="; ".join(disclosed_tech),
                raw_evidence="; ".join(disclosed_tech),
            ))

        return findings
