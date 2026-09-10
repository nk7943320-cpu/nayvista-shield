"""
SentinelScan - HTTP Security Headers Scanner
Analyzes HTTP responses for missing or misconfigured security headers.
Evaluates:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
"""

from typing import List, Dict, Any
from scanner.crawler import CrawledPage
from scanner.normalizer import create_finding

class HeadersScanner:
    def scan(self, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not pages:
            return findings

        # Typically evaluate headers on the primary/landing page or distinct HTML pages
        target_page = pages[0]
        headers = {k.lower(): v for k, v in target_page.headers.items()}
        page_url = target_page.url

        # 1. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(create_finding(
                scanner="headers_scanner",
                title="Content Security Policy (CSP) Missing",
                severity="MEDIUM",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=page_url,
                evidence="No 'Content-Security-Policy' response header was returned.",
                description="Content Security Policy is an effective defense-in-depth mechanism against Cross-Site Scripting (XSS) and data injection attacks.",
                impact="Without CSP, browser execution of untrusted inline scripts or cross-site payloads is not restricted.",
                remediation="Configure a Content-Security-Policy header specifying trusted sources for scripts, styles, and objects (e.g., default-src 'self')."
            ))
        else:
            # Check for overly permissive CSP directives
            csp_lower = csp.lower()
            if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
                findings.append(create_finding(
                    scanner="headers_scanner",
                    title="Content Security Policy Contains Unsafe Directives",
                    severity="LOW",
                    confidence="HIGH",
                    category="Security Misconfiguration",
                    owasp_key="SECURITY_MISCONFIGURATION",
                    url=page_url,
                    evidence=f"CSP header contains unsafe directive: {csp[:120]}...",
                    description="The CSP policy includes 'unsafe-inline' or 'unsafe-eval', weakening script execution boundaries.",
                    impact="Attackers who inject script tags may still achieve code execution in the user's browser.",
                    remediation="Refactor inline scripts to external files and use nonces or cryptographic hashes instead of 'unsafe-inline'."
                ))

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        is_https = page_url.lower().startswith("https://")
        if is_https:
            if not hsts:
                findings.append(create_finding(
                    scanner="headers_scanner",
                    title="HTTP Strict Transport Security (HSTS) Missing",
                    severity="LOW",
                    confidence="HIGH",
                    category="Cryptographic Failures",
                    owasp_key="CRYPTOGRAPHIC_FAILURES",
                    url=page_url,
                    evidence="No 'Strict-Transport-Security' response header was present on this HTTPS service.",
                    description="HSTS instructs compliant browsers to only communicate over HTTPS, mitigating SSL stripping and accidental cleartext requests.",
                    impact="Initial insecure HTTP connections could be intercepted or downgraded by an active network adversary.",
                    remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on all HTTPS responses."
                ))
            else:
                if "max-age" in hsts.lower():
                    # Parse max-age seconds
                    try:
                        parts = [p.strip() for p in hsts.split(";")]
                        for p in parts:
                            if p.lower().startswith("max-age="):
                                age_val = int(p.split("=")[1].strip())
                                if age_val < 10886400: # ~126 days
                                    findings.append(create_finding(
                                        scanner="headers_scanner",
                                        title="HSTS Max-Age Duration Too Short",
                                        severity="LOW",
                                        confidence="HIGH",
                                        category="Cryptographic Failures",
                                        owasp_key="CRYPTOGRAPHIC_FAILURES",
                                        url=page_url,
                                        evidence=f"Strict-Transport-Security max-age is set to {age_val} seconds.",
                                        description="HSTS max-age should ideally be at least 1 year (31536000 seconds) for effective protection.",
                                        impact="Short policy duration increases the window of exposure if the user does not visit frequently.",
                                        remediation="Increase the HSTS max-age to at least 31536000 seconds."
                                    ))
                    except Exception:
                        pass

        # 3. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            findings.append(create_finding(
                scanner="headers_scanner",
                title="X-Content-Type-Options Header Missing",
                severity="LOW",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=page_url,
                evidence=f"X-Content-Type-Options header: '{xcto or 'NOT PRESENT'}'",
                description="The 'X-Content-Type-Options: nosniff' header prevents browsers from MIME-sniffing a response away from the declared content type.",
                impact="MIME-sniffing could allow untrusted user uploads (like images) to be executed as HTML or JavaScript.",
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses."
            ))

        # 4. X-Frame-Options (Clickjacking defense if not handled by CSP)
        xfo = headers.get("x-frame-options")
        has_csp_frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if not xfo and not has_csp_frame_ancestors:
            findings.append(create_finding(
                scanner="headers_scanner",
                title="Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)",
                severity="MEDIUM",
                confidence="HIGH",
                category="Broken Access Control",
                owasp_key="BROKEN_ACCESS_CONTROL",
                url=page_url,
                evidence="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was configured.",
                description="Frame protection prevents the website from being embedded inside malicious iframes, stopping clickjacking attacks.",
                impact="An attacker could frame this page on a third-party site to trick users into triggering unintended actions.",
                remediation="Configure 'X-Frame-Options: SAMEORIGIN' or CSP 'frame-ancestors 'self''."
            ))

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        if not ref_pol:
            findings.append(create_finding(
                scanner="headers_scanner",
                title="Referrer-Policy Header Missing",
                severity="LOW",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=page_url,
                evidence="No 'Referrer-Policy' header was observed.",
                description="Referrer-Policy controls how much referrer information is included with requests made from the document.",
                impact="Sensitive URLs with tokens or user paths might leak in the Referer header to external origins.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            ))
        elif ref_pol.lower().strip() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(create_finding(
                scanner="headers_scanner",
                title="Insecure Referrer-Policy Configuration",
                severity="LOW",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=page_url,
                evidence=f"Referrer-Policy is set to '{ref_pol}'.",
                description="Using permissive referrer policies may expose internal URLs or parameters to third parties.",
                impact="Private paths and query parameters can leak across origins.",
                remediation="Update Referrer-Policy to 'strict-origin-when-cross-origin'."
            ))

        # 6. Permissions-Policy
        perm_pol = headers.get("permissions-policy") or headers.get("feature-policy")
        if not perm_pol:
            findings.append(create_finding(
                scanner="headers_scanner",
                title="Permissions-Policy Header Missing",
                severity="INFO",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=page_url,
                evidence="No 'Permissions-Policy' header was specified.",
                description="Permissions-Policy restricts browser features like camera, microphone, and geolocation from being used inadvertently.",
                impact="Malicious third-party scripts or embedded widgets could request sensitive browser hardware permissions.",
                remediation="Deploy a Permissions-Policy header restricting unused browser APIs (e.g., 'geolocation=(), camera=(), microphone=()')."
            ))

        return findings
