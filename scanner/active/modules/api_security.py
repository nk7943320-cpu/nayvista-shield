"""
NayVista Shield - Active API Security Validation Module
Audits API endpoints for OpenAPI exposure, Content-Type hygiene, and unauthenticated data leaks.
"""

import json
from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class APISecurityValidationModule(ActiveModule):
    name = "APISecurityValidation"
    description = "Active audit of API schemas, JSON response headers, and unauthenticated data exposure"
    stage_name = "API Security"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("API Security")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        api_endpoints = list(context.get("api_endpoints", []))
        if not api_endpoints:
            # Probe standard swagger / openapi fallback if not already found
            from urllib.parse import urljoin
            for p in ("/openapi.json", "/swagger.json", "/api/v1"):
                u = urljoin(target, p)
                resp = await controller.request("GET", u)
                if resp and resp.status_code == 200:
                    api_endpoints.append(u)

        for api_url in api_endpoints[:5]:
            resp = await controller.request("GET", api_url)
            if not resp or resp.status_code != 200:
                continue

            content_type = resp.headers.get("content-type", "").lower()

            # 1. Swagger / OpenAPI schema exposed publicly
            if "openapi" in resp.text or "swagger" in resp.text:
                try:
                    data = json.loads(resp.text)
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                        findings.append(self.create_finding(
                            title="Publicly Accessible OpenAPI / Swagger Specification",
                            severity="LOW",
                            confidence="CONFIRMED",
                            owasp="A05:2021-Security Misconfiguration",
                            cwe="CWE-200",
                            description=f"Complete OpenAPI/Swagger schema is publicly accessible at {api_url} without authentication.",
                            impact="Provides comprehensive mapping of internal API routes, parameter names, and schemas to unauthenticated parties.",
                            remediation="Restrict API documentation to authorized development and staging environments.",
                            target_url=target,
                            endpoint=api_url,
                            test_performed="GET API schema retrieval and JSON schema parsing",
                            expected="Schema should require authentication or be restricted to internal networks",
                            observed=f"Valid schema parsed (OpenAPI/Swagger version: {data.get('openapi') or data.get('swagger')})",
                            raw_evidence=f"Title: {data.get('info', {}).get('title', 'API Schema')}",
                        ))
                except Exception:
                    pass

            # 2. Check for sensitive data leakage in JSON responses
            if "application/json" in content_type:
                lower_text = resp.text.lower()
                sensitive_tokens = ["password_hash", "private_key", "secret_token", "admin_pass", "db_password"]
                matched_tokens = [tok for tok in sensitive_tokens if tok in lower_text]
                if matched_tokens:
                    findings.append(self.create_finding(
                        title="Sensitive Credential Fields Exposed in Unauthenticated API Response",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-200",
                        description=f"API endpoint {api_url} returned responses containing sensitive credential identifiers: {', '.join(matched_tokens)}.",
                        impact="Critical disclosure of secrets or password hashes allows account takeover or database compromise.",
                        remediation="Filter sensitive model attributes from API serializer and enforce authentication.",
                        target_url=target,
                        endpoint=api_url,
                        test_performed="JSON API response inspection for confidential keys",
                        expected="Absence of secret or password fields in public responses",
                        observed=f"Sensitive keys identified: {', '.join(matched_tokens)}",
                        raw_evidence=f"Matched: {matched_tokens}",
                    ))

        return findings
