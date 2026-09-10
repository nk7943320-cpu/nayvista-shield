"""
NayVista Shield - Active Cookie & Session Security Validation Module
Audits Set-Cookie security flags: Secure, HttpOnly, SameSite, and session hygiene.
"""

from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class CookieSessionValidationModule(ActiveModule):
    name = "CookieSessionValidation"
    description = "Active cookie security flag analysis (Secure, HttpOnly, SameSite)"
    stage_name = "Cookie Security"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Cookie Security")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        resp = await controller.request("GET", target)
        if not resp:
            return findings

        # Look for set-cookie headers
        cookie_headers: List[str] = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                cookie_headers.append(v)

        if not cookie_headers:
            return findings

        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            cookie_keyval = parts[0].split("=", 1)
            cookie_name = cookie_keyval[0].strip()
            cookie_val = cookie_keyval[1].strip() if len(cookie_keyval) > 1 else ""

            # Check flags
            lower_parts = [p.lower() for p in parts[1:]]
            has_secure = any(p == "secure" for p in lower_parts)
            has_httponly = any(p == "httponly" for p in lower_parts)
            samesite_part = next((p for p in lower_parts if p.startswith("samesite")), None)

            is_session_like = any(
                s in cookie_name.lower()
                for s in ("session", "token", "auth", "sid", "jwt", "connect.sid", "phpsessid", "jsessionid")
            )

            # Check Secure flag
            if not has_secure and controller.scope_policy.primary_scheme == "https":
                severity = "HIGH" if is_session_like else "LOW"
                findings.append(self.create_finding(
                    title=f"Cookie Missing 'Secure' Attribute ({cookie_name})",
                    severity=severity,
                    confidence="CONFIRMED",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-614",
                    description=f"Cookie '{cookie_name}' is set without the 'Secure' attribute over an HTTPS origin.",
                    impact="Clients can transmit the cookie over unencrypted HTTP connections, exposing it to interception.",
                    remediation=f"Add the '; Secure' flag to Set-Cookie header for '{cookie_name}'.",
                    target_url=target,
                    endpoint=target,
                    test_performed=f"Set-Cookie attribute inspection for '{cookie_name}'",
                    expected="Cookie header must contain '; Secure'",
                    observed=f"Set-Cookie: {cookie_name}=[REDACTED]; {'; '.join(parts[1:])}",
                    raw_evidence=f"Name: {cookie_name}, Flags: {parts[1:]}",
                ))

            # Check HttpOnly flag
            if not has_httponly and is_session_like:
                findings.append(self.create_finding(
                    title=f"Session Cookie Missing 'HttpOnly' Attribute ({cookie_name})",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1004",
                    description=f"Authentication or session cookie '{cookie_name}' lacks the 'HttpOnly' attribute.",
                    impact="If a Cross-Site Scripting (XSS) vulnerability exists, malicious JavaScript can access and steal the session token.",
                    remediation=f"Add '; HttpOnly' to Set-Cookie directive for '{cookie_name}'.",
                    target_url=target,
                    endpoint=target,
                    test_performed=f"Set-Cookie HttpOnly attribute check for session token '{cookie_name}'",
                    expected="Session cookie must include '; HttpOnly'",
                    observed="HttpOnly attribute absent",
                    raw_evidence=f"Name: {cookie_name}, Flags: {parts[1:]}",
                ))

            # Check SameSite attribute
            if not samesite_part:
                findings.append(self.create_finding(
                    title=f"Cookie Missing 'SameSite' Attribute ({cookie_name})",
                    severity="LOW",
                    confidence="CONFIRMED",
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-1275",
                    description=f"Cookie '{cookie_name}' does not specify a SameSite attribute (Lax or Strict).",
                    impact="Lack of SameSite attribute increases risk of Cross-Site Request Forgery (CSRF) on older user agents.",
                    remediation=f"Specify '; SameSite=Lax' or '; SameSite=Strict' on Set-Cookie for '{cookie_name}'.",
                    target_url=target,
                    endpoint=target,
                    test_performed=f"Set-Cookie SameSite attribute audit for '{cookie_name}'",
                    expected="Cookie should specify '; SameSite=Lax' or '; SameSite=Strict'",
                    observed="SameSite attribute omitted",
                    raw_evidence=f"Name: {cookie_name}, Flags: {parts[1:]}",
                ))

        return findings
