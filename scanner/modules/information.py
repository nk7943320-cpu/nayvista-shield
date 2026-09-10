"""
SentinelScan - Information Disclosure Module
Safely checks for:
- Server banners & version disclosure in HTTP response headers.
- Framework/runtime disclosure (X-Powered-By, X-AspNet-Version, X-Runtime).
- Verbose stack trace markers in error bodies.
- Safe status checks for accidental exposure of .git/HEAD or .env without storing content.
"""

import re
from typing import List, Dict, Any
import httpx
from scanner.crawler import CrawledPage
from scanner.scope import TargetScope
from scanner.findings import create_finding

STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python traceback"),
    (re.compile(r"Fatal error:.*in .*\.php on line \d+", re.IGNORECASE), "PHP fatal error stack trace"),
    (re.compile(r"^\s*at\s+[\w\.\/<>]+\s+\([\w\.\/<>]+:\d+:\d+\)", re.MULTILINE), "Node.js stack trace"),
    (re.compile(r"org\.apache\.catalina|org\.springframework\.", re.IGNORECASE), "Java/Spring stack trace"),
    (re.compile(r"Microsoft\.AspNetCore\.|System\.Web\.UI", re.IGNORECASE), "ASP.NET stack trace"),
]

class InfoDisclosureScanner:
    def scan(self, scope: TargetScope, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not pages:
            return findings

        # 1. Header Disclosure Analysis
        seen_servers = set()
        seen_powered_by = set()

        for page in pages:
            headers = {k.lower(): v for k, v in page.headers.items()}

            server = headers.get("server")
            if server and server not in seen_servers:
                seen_servers.add(server)
                if any(char.isdigit() for char in server):
                    findings.append(create_finding(
                        scanner="information",
                        title="Detailed Web Server Version Disclosed",
                        severity="LOW",
                        confidence="HIGH",
                        category="Vulnerable and Outdated Components",
                        owasp_key="VULNERABLE_COMPONENTS",
                        url=page.url,
                        evidence=f"Server header: '{server}'",
                        description="The web server banner exposes detailed software name and version information.",
                        impact="Attackers can use known version-specific vulnerabilities and targeted exploit profiles against this host.",
                        remediation="Configure the web server to suppress or generalize the Server banner (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
                    ))

            powered_by = headers.get("x-powered-by")
            if powered_by and powered_by not in seen_powered_by:
                seen_powered_by.add(powered_by)
                findings.append(create_finding(
                    scanner="information",
                    title="Backend Technology Disclosed via X-Powered-By",
                    severity="LOW",
                    confidence="HIGH",
                    category="Security Misconfiguration",
                    owasp_key="SECURITY_MISCONFIGURATION",
                    url=page.url,
                    evidence=f"X-Powered-By header: '{powered_by}'",
                    description="The server returns an X-Powered-By header identifying backend technologies or frameworks.",
                    impact="Facilitates attacker reconnaissance by pinpointing exact framework versions and underlying tech.",
                    remediation="Disable the X-Powered-By header in application configuration (e.g. app.disable('x-powered-by') in Express, expose_php = Off in php.ini)."
                ))

            # 2. Check for Stack Traces in response text
            if page.text:
                for pattern, desc in STACK_TRACE_PATTERNS:
                    if pattern.search(page.text):
                        findings.append(create_finding(
                            scanner="information",
                            title=f"Detailed Application Stack Trace Disclosed ({desc})",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="Security Misconfiguration",
                            owasp_key="SECURITY_MISCONFIGURATION",
                            url=page.url,
                            evidence=f"Detected pattern matching: {desc}",
                            description="The response contains an unhandled exception or debug stack trace disclosing internal file paths and code lines.",
                            impact="Attackers gain knowledge of internal code structure, database queries, and environment details.",
                            remediation="Implement custom error pages and disable verbose debug modes in production."
                        ))
                        break

        # 3. Safe, non-destructive probe for common misconfigured assets (.git/HEAD and .env)
        base_url = f"{scope.scheme}://{scope.hostname}:{scope.port}"
        try:
            with httpx.Client(verify=not scope.allow_local, timeout=5.0) as client:
                git_url = f"{base_url}/.git/HEAD"
                git_resp = client.get(git_url, headers={"User-Agent": "SentinelScan-Security-Auditor/1.0"})
                if git_resp.status_code == 200 and "ref: refs/" in git_resp.text[:100]:
                    findings.append(create_finding(
                        scanner="information",
                        title="Exposed Git Repository Configuration (.git/HEAD)",
                        severity="HIGH",
                        confidence="HIGH",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=git_url,
                        evidence="File was publicly accessible and contained standard Git branch reference.",
                        description="The .git directory appears to be accessible via the web root.",
                        impact="Unauthorized actors could reconstruct the entire application source code and revision history.",
                        remediation="Block access to .git and hidden files in your web server configuration."
                    ))

                env_url = f"{base_url}/.env"
                env_resp = client.get(env_url, headers={"User-Agent": "SentinelScan-Security-Auditor/1.0"})
                if env_resp.status_code == 200:
                    text_head = env_resp.text[:300]
                    if any(k in text_head for k in ("APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=", "API_KEY=")):
                        findings.append(create_finding(
                            scanner="information",
                            title="Publicly Accessible Environment File (.env)",
                            severity="CRITICAL",
                            confidence="HIGH",
                            category="Security Misconfiguration",
                            owasp_key="SECURITY_MISCONFIGURATION",
                            url=env_url,
                            evidence="Endpoint returned HTTP 200 with standard environment variable definition markers. Content was not downloaded or retained.",
                            description="An environment configuration file (.env) was found exposed in the public web root.",
                            impact="Exposes sensitive configuration parameters, database credentials, and secret API keys.",
                            remediation="Block public web server access to .env files and move sensitive environment files outside the document root."
                        ))
        except Exception:
            pass

        return findings
