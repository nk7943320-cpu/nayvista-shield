"""
NayVista Shield - Active Information Exposure Validation Module
Inspects responses for leaked secrets, API keys, private keys, and database stack traces.
"""

import re
from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "CRITICAL", "CWE-798"),
    ("Google API Key", re.compile(r'\b(AIza[0-9A-Za-z\\-_]{35})\b'), "HIGH", "CWE-798"),
    ("Slack API Token", re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'), "HIGH", "CWE-798"),
    ("Private Key Header", re.compile(r'(-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----)'), "CRITICAL", "CWE-312"),
    ("Database / Stack Trace", re.compile(r'(Traceback \(most recent call last\):|SQL syntax.*MySQL|PostgreSQL.*ERROR|org\.hibernate\.exception)'), "MEDIUM", "CWE-209"),
]

class InformationExposureModule(ActiveModule):
    name = "InformationExposure"
    description = "Active analysis for leaked credentials, API tokens, private keys, and stack traces"
    stage_name = "Information Exposure"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Information Exposure")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        endpoints_to_check = [target]
        discovered = list(context.get("discovered_endpoints", []))
        endpoints_to_check.extend(discovered[:5])

        for page_url in endpoints_to_check:
            resp = await controller.request("GET", page_url)
            if not resp or resp.status_code != 200:
                continue

            content = resp.text
            for title, pattern, severity, cwe in SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_str = match.group(0)
                    findings.append(self.create_finding(
                        title=f"Sensitive Data Exposure: {title}",
                        severity=severity,
                        confidence="CONFIRMED",
                        owasp="A01:2021-Broken Access Control" if "Key" in title else "A05:2021-Security Misconfiguration",
                        cwe=cwe,
                        description=f"Response body at {page_url} contains exposed sensitive data matching pattern for {title}.",
                        impact="Exposed API keys or database traces facilitate account compromise, data exfiltration, or targeted exploits.",
                        remediation="Revoke exposed credentials immediately. Move secrets to environment variables and disable verbose stack traces in production.",
                        target_url=target,
                        endpoint=page_url,
                        test_performed=f"Regex pattern validation for {title}",
                        expected="Clean production responses without leaked credentials or debug traces",
                        observed=f"Matched pattern for {title}",
                        raw_evidence=f"Token: {matched_str[:6]}...[REDACTED]",
                    ))

        return findings
