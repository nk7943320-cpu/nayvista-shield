"""
SentinelScan - Cookie Security Module
Analyzes cookies for missing security flags: Secure, HttpOnly, SameSite, and broad Domain/Path.
Strict privacy rule: Never log or display sensitive cookie values.
"""

from typing import List, Dict, Any
from scanner.crawler import CrawledPage
from scanner.findings import create_finding

class CookieScanner:
    def scan(self, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        observed_cookies = set()

        for page in pages:
            set_cookie_raw = None
            for k, v in page.headers.items():
                if k.lower() == "set-cookie":
                    set_cookie_raw = v
                    break

            if not set_cookie_raw:
                continue

            raw_cookies = [c.strip() for c in set_cookie_raw.split("\n")] if "\n" in set_cookie_raw else [set_cookie_raw]

            for cookie_str in raw_cookies:
                parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
                if not parts:
                    continue

                name_val = parts[0].split("=", 1)
                cookie_name = name_val[0].strip()
                if not cookie_name:
                    continue

                if cookie_name in observed_cookies:
                    continue
                observed_cookies.add(cookie_name)

                flags = {p.lower().split("=")[0]: p for p in parts[1:]}
                is_https = page.url.lower().startswith("https://")

                sanitized_flags = "; ".join([p for p in parts[1:]])
                sanitized_cookie_repr = f"{cookie_name}=[REDACTED]; {sanitized_flags}".strip("; ")

                # 1. Secure flag
                if "secure" not in flags and is_https:
                    findings.append(create_finding(
                        scanner="cookies",
                        title=f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                        severity="MEDIUM",
                        confidence="HIGH",
                        category="Cryptographic Failures",
                        owasp_key="CRYPTOGRAPHIC_FAILURES",
                        url=page.url,
                        evidence=f"Observed Set-Cookie: {sanitized_cookie_repr}",
                        description=f"The cookie '{cookie_name}' was set on an HTTPS connection without the 'Secure' attribute.",
                        impact="Browsers may transmit this cookie in cleartext over unencrypted HTTP requests, exposing session credentials to eavesdroppers.",
                        remediation=f"Append '; Secure' to the Set-Cookie directive for '{cookie_name}'."
                    ))

                # 2. HttpOnly flag
                if "httponly" not in flags:
                    findings.append(create_finding(
                        scanner="cookies",
                        title=f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        severity="MEDIUM",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence=f"Observed Set-Cookie: {sanitized_cookie_repr}",
                        description=f"The cookie '{cookie_name}' does not specify the 'HttpOnly' flag.",
                        impact="The cookie is accessible to client-side JavaScript via document.cookie, making it vulnerable to theft via Cross-Site Scripting (XSS).",
                        remediation=f"Append '; HttpOnly' to the Set-Cookie directive for '{cookie_name}' unless explicit client-side JS access is required."
                    ))

                # 3. SameSite flag
                samesite_found = False
                samesite_val = ""
                for k, v in flags.items():
                    if k.startswith("samesite"):
                        samesite_found = True
                        if "=" in v:
                            samesite_val = v.split("=")[1].strip().lower()

                if not samesite_found:
                    findings.append(create_finding(
                        scanner="cookies",
                        title=f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                        severity="LOW",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence=f"Observed Set-Cookie: {sanitized_cookie_repr}",
                        description=f"The cookie '{cookie_name}' lacks a SameSite attribute (Lax, Strict, or None).",
                        impact="Without explicit SameSite controls, the cookie may be sent with cross-site requests, increasing exposure to Cross-Site Request Forgery (CSRF).",
                        remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' for the '{cookie_name}' cookie."
                    ))
                elif samesite_val == "none" and "secure" not in flags:
                    findings.append(create_finding(
                        scanner="cookies",
                        title=f"Cookie '{cookie_name}' Configured with SameSite=None without Secure",
                        severity="MEDIUM",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence=f"Observed Set-Cookie: {sanitized_cookie_repr}",
                        description=f"Cookie '{cookie_name}' specifies SameSite=None without the Secure attribute.",
                        impact="Modern browsers will reject this cookie, or it will be transmitted over insecure channels.",
                        remediation=f"Ensure 'Secure' is included whenever 'SameSite=None' is declared."
                    ))

                # 4. Domain attribute
                for k, v in flags.items():
                    if k.startswith("domain="):
                        dom_val = v.split("=")[1].strip()
                        if dom_val.startswith("."):
                            findings.append(create_finding(
                                scanner="cookies",
                                title=f"Cookie '{cookie_name}' Configured with Broad Domain Scope",
                                severity="LOW",
                                confidence="MEDIUM",
                                category="Security Misconfiguration",
                                owasp_key="SECURITY_MISCONFIGURATION",
                                url=page.url,
                                evidence=f"Cookie Domain attribute is '{dom_val}'",
                                description=f"The cookie '{cookie_name}' specifies a loose domain scope starting with a dot.",
                                impact="Subdomains on the same parent domain can read or overwrite this cookie, expanding attack surface.",
                                remediation="Omit the domain attribute to restrict the cookie strictly to the origin host."
                            ))

        return findings
