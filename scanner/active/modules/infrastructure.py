"""
NayVista Shield - Active Infrastructure Exposure Validation Module
Audits public exposure of Git repositories, environment files, phpinfo, and server status.
"""

from typing import Dict, Any, List
from urllib.parse import urljoin
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

INFRASTRUCTURE_TARGETS = [
    ("/.git/HEAD", "Git Repository Exposure (/.git/HEAD)", "CRITICAL", "ref: refs/"),
    ("/.env", "Environment Configuration File Exposure (/.env)", "CRITICAL", "app_key="),
    ("/phpinfo.php", "PHP Information Leakage (/phpinfo.php)", "MEDIUM", "<title>phpinfo()"),
    ("/server-status", "Web Server Status Page Exposure (/server-status)", "MEDIUM", "apache status"),
    ("/.svn/entries", "Subversion Repository Exposure (/.svn/entries)", "HIGH", "dir"),
    ("/.DS_Store", "macOS Directory Artifact Exposure (/.DS_Store)", "LOW", "\x00\x00\x00\x01bud1"),
]

class InfrastructureExposureModule(ActiveModule):
    name = "InfrastructureExposure"
    description = "Active probe for exposed Git repos, .env configuration files, and server status pages"
    stage_name = "Infrastructure Exposure"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Infrastructure Exposure")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        for path, title, severity, signature in INFRASTRUCTURE_TARGETS:
            probe_url = urljoin(target, path)
            resp = await controller.request("GET", probe_url)
            if not resp or resp.status_code != 200:
                continue

            lower_text = resp.text.lower()
            matched = False

            if path == "/.git/HEAD":
                if resp.text.strip().startswith("ref: refs/") or "ref: " in resp.text:
                    matched = True
            elif path == "/.env":
                env_keys = ["db_", "app_", "secret_", "aws_", "api_", "password="]
                if any(k in lower_text for k in env_keys):
                    matched = True
            elif path == "/phpinfo.php":
                if "php version" in lower_text or "phpinfo()" in lower_text:
                    matched = True
            elif path == "/server-status":
                if "server version:" in lower_text or "apache status" in lower_text:
                    matched = True
            elif signature and signature.lower() in lower_text:
                matched = True

            if matched:
                findings.append(self.create_finding(
                    title=title,
                    severity=severity,
                    confidence="CONFIRMED",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-200",
                    description=f"Critical infrastructure artifact {path} is publicly exposed on the web server.",
                    impact="Adversaries can download complete source code history, secrets, or internal server configurations.",
                    remediation=f"Block public access to {path} at the web server / proxy level and remove files from document root.",
                    target_url=target,
                    endpoint=probe_url,
                    test_performed=f"GET {path} artifact signature verification",
                    expected="HTTP 404 Not Found or HTTP 403 Forbidden",
                    observed=f"HTTP 200 with signature match: {resp.text[:100].strip()}",
                    raw_evidence=f"Content sample: {resp.text[:120].strip()}",
                ))

        return findings
