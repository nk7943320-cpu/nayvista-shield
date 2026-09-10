"""
NayVista Shield - Active CORS Validation Module
Probes Cross-Origin Resource Sharing policy for origin reflection and credential exposure risks.
"""

from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

BENIGN_TEST_ORIGIN = "https://untrusted-security-test.local"

class CORSValidationModule(ActiveModule):
    name = "CORSValidation"
    description = "Active CORS probe for origin reflection, wildcard exposure, and credential leakage"
    stage_name = "CORS Validation"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("CORS Validation")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        # Test with custom untrusted Origin
        headers = {"Origin": BENIGN_TEST_ORIGIN}
        resp = await controller.request("GET", target, headers=headers)
        if not resp:
            return findings

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        # 1. Arbitrary Origin Reflection with Credentials Allowed
        if acao == BENIGN_TEST_ORIGIN and acac:
            findings.append(self.create_finding(
                title="Overly Permissive CORS Configuration (Arbitrary Origin Reflection with Credentials)",
                severity="CRITICAL",
                confidence="CONFIRMED",
                owasp="A01:2021-Broken Access Control",
                cwe="CWE-942",
                description="The server reflects arbitrary client-supplied Origin headers and explicitly enables Access-Control-Allow-Credentials.",
                impact="Enables cross-origin data theft: a malicious third-party site can make authenticated cross-origin requests and read sensitive responses.",
                remediation="Validate Origin against a strict whitelist of trusted domains and never blindly reflect user-supplied Origin headers with credentials enabled.",
                target_url=target,
                endpoint=target,
                test_performed=f"GET request with Origin: {BENIGN_TEST_ORIGIN}",
                expected="No Access-Control-Allow-Origin reflection or rejection of untrusted origin",
                observed=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
                raw_evidence=f"ACAO: {acao}, ACAC: {acac}",
            ))
        elif acao == BENIGN_TEST_ORIGIN:
            findings.append(self.create_finding(
                title="Arbitrary Origin Reflection in CORS (Access-Control-Allow-Origin)",
                severity="MEDIUM",
                confidence="CONFIRMED",
                owasp="A01:2021-Broken Access Control",
                cwe="CWE-942",
                description="The application dynamically reflects unvalidated Origin headers in Access-Control-Allow-Origin.",
                impact="Allows unauthorized domains to read unauthenticated responses and exposes cross-origin attack vectors.",
                remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist of authorized domain names.",
                target_url=target,
                endpoint=target,
                test_performed=f"GET request with Origin: {BENIGN_TEST_ORIGIN}",
                expected="Static trusted origin or omission of ACAO header",
                observed=f"Access-Control-Allow-Origin: {acao}",
                raw_evidence=f"ACAO: {acao}",
            ))

        # Test with Origin: null
        resp_null = await controller.request("GET", target, headers={"Origin": "null"})
        if resp_null:
            null_acao = resp_null.headers.get("access-control-allow-origin", "")
            null_acac = resp_null.headers.get("access-control-allow-credentials", "").lower() == "true"
            if null_acao == "null" and null_acac:
                findings.append(self.create_finding(
                    title="Insecure CORS Policy Allowing 'null' Origin with Credentials",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-942",
                    description="The server permits the 'null' origin and enables Access-Control-Allow-Credentials: true.",
                    impact="Sandboxed iframes and local HTML files run with 'null' origin, allowing local attackers or sandboxed frames to access user data.",
                    remediation="Do not include 'null' in Access-Control-Allow-Origin headers.",
                    target_url=target,
                    endpoint=target,
                    test_performed="GET request with Origin: null",
                    expected="Origin: null should be rejected",
                    observed="Access-Control-Allow-Origin: null with credentials true",
                    raw_evidence=f"ACAO: {null_acao}, ACAC: {null_acac}",
                ))

        return findings
