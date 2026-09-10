"""
NayVista Shield - Active HTTP Behavior Validation Module
Validates HTTP-to-HTTPS redirect enforcement, HTTP verb tampering, and open redirect parameters.
"""

from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

BENIGN_REDIRECT_TARGET = "https://example.com"

class HTTPBehaviorValidationModule(ActiveModule):
    name = "HTTPBehaviorValidation"
    description = "Active validation of HTTP-to-HTTPS redirects, verb tampering, and open redirects"
    stage_name = "HTTP Behavior"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("HTTP Behavior")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target
        scope = controller.scope_policy.target_scope

        # 1. HTTP to HTTPS redirect enforcement (if site is HTTPS)
        if scope.scheme == "https":
            http_url = f"http://{scope.hostname}:{80 if scope.port == 443 else scope.port}/"
            try:
                # We do a direct request check for redirect
                client = await controller.get_client()
                resp = await client.request("GET", http_url, follow_redirects=False, timeout=4.0)
                if resp.status_code not in (301, 308):
                    findings.append(self.create_finding(
                        title="HTTP Traffic Not Permanently Redirected to HTTPS (301/308)",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-319",
                        description=f"Initial cleartext connection to {http_url} returned HTTP {resp.status_code} instead of a permanent 301/308 redirect to HTTPS.",
                        impact="Clients accessing the application without typing 'https://' may transmit initial requests over unencrypted HTTP.",
                        remediation="Configure web server or load balancer to issue permanent HTTP 301/308 redirects from HTTP to HTTPS.",
                        target_url=target,
                        endpoint=http_url,
                        test_performed=f"GET {http_url} protocol redirect verification",
                        expected="HTTP 301/308 Redirect to HTTPS",
                        observed=f"HTTP {resp.status_code}",
                        raw_evidence=f"Status: {resp.status_code}, Location: {resp.headers.get('location')}",
                    ))
            except Exception:
                pass

        # 2. Verb Tampering / Inconsistent HTTP Method Behavior
        # If any endpoint returned 401 or 403 under GET, test HEAD
        discovered = list(context.get("discovered_endpoints", []))
        for endp in discovered[:3]:
            get_resp = await controller.request("GET", endp)
            if get_resp and get_resp.status_code in (401, 403):
                head_resp = await controller.request("HEAD", endp)
                if head_resp and head_resp.status_code == 200:
                    findings.append(self.create_finding(
                        title=f"HTTP Verb Tampering Bypass Risk ({endp})",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-654",
                        description=f"Endpoint {endp} restricts GET with HTTP {get_resp.status_code} but accepts HEAD with HTTP 200 OK.",
                        impact="Security controls implemented via HTTP method filters can be bypassed by using alternate HTTP methods.",
                        remediation="Apply authentication and authorization filters uniformly to all HTTP verbs.",
                        target_url=target,
                        endpoint=endp,
                        test_performed="GET vs HEAD response code differential audit",
                        expected="Uniform access restriction across all verbs",
                        observed=f"GET returned {get_resp.status_code} but HEAD returned 200",
                        raw_evidence=f"GET: {get_resp.status_code}, HEAD: {head_resp.status_code}",
                    ))

        # 3. Open Redirect Validation (safe, non-destructive probe with benign target)
        redirect_params = ["next", "redirect", "url", "return", "dest"]
        for param in redirect_params:
            probe_url = f"{target}?{param}={BENIGN_REDIRECT_TARGET}"
            # Send single non-following request
            client = await controller.get_client()
            try:
                resp = await client.request("GET", probe_url, follow_redirects=False, timeout=4.0)
                if resp.is_redirect:
                    loc = resp.headers.get("location", "")
                    if loc.startswith(BENIGN_REDIRECT_TARGET):
                        findings.append(self.create_finding(
                            title=f"Unvalidated Open Redirect via Parameter '?{param}='",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            owasp="A01:2021-Broken Access Control",
                            cwe="CWE-601",
                            description=f"The application accepted external target '{BENIGN_REDIRECT_TARGET}' in parameter '{param}' and issued a direct redirect.",
                            impact="Attackers can craft phishing links utilizing the trusted domain to forward victims to malicious credential-harvesting sites.",
                            remediation="Validate redirection targets against a strict allowlist of same-origin paths or trusted URLs.",
                            target_url=target,
                            endpoint=probe_url,
                            test_performed=f"GET probe with parameter ?{param}={BENIGN_REDIRECT_TARGET}",
                            expected="Rejection or sanitization of external redirect target",
                            observed=f"Location header: {loc}",
                            raw_evidence=f"Status: {resp.status_code}, Location: {loc}",
                        ))
                        break
            except Exception:
                pass

        return findings
