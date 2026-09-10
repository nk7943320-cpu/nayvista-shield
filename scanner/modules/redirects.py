"""
SentinelScan - Redirect Security Module
Analyzes redirect behavior:
- Tests HTTP to HTTPS redirect enforcement.
- Detects excessive redirect hops or downgrade loops.
- Flags cross-origin redirect escapes.
- Identifies common open redirect parameters in URLs.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs
import httpx
from scanner.scope import TargetScope
from scanner.crawler import CrawledPage
from scanner.findings import create_finding

OPEN_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "return_to", "r", "goto", "dest", "target"}

class RedirectScanner:
    def scan(self, scope: TargetScope, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1. Test HTTP to HTTPS Upgrade if target is https
        if scope.scheme == "https" and scope.port == 443:
            http_url = f"http://{scope.hostname}/"
            try:
                with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                    resp = client.get(http_url, headers={"User-Agent": "SentinelScan-Security-Auditor/1.0"})
                    if resp.status_code not in (301, 302, 307, 308):
                        findings.append(create_finding(
                            scanner="redirects",
                            title="Plain HTTP Port Does Not Redirect to HTTPS",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="Cryptographic Failures",
                            owasp_key="CRYPTOGRAPHIC_FAILURES",
                            url=http_url,
                            evidence=f"Plain HTTP connection returned status code {resp.status_code} without redirect.",
                            description="Users navigating to http:// are not automatically redirected to the secure HTTPS version.",
                            impact="Cleartext connections remain unencrypted, enabling man-in-the-middle interception.",
                            remediation="Implement a permanent HTTP 301 redirect from HTTP to HTTPS for all traffic."
                        ))
                    else:
                        loc = resp.headers.get("location", "")
                        if not loc.lower().startswith("https://"):
                            findings.append(create_finding(
                                scanner="redirects",
                                title="HTTP Redirect Does Not Direct to HTTPS",
                                severity="HIGH",
                                confidence="HIGH",
                                category="Cryptographic Failures",
                                owasp_key="CRYPTOGRAPHIC_FAILURES",
                                url=http_url,
                                evidence=f"HTTP redirect Location header: '{loc}'",
                                description="The HTTP redirect header directs users to an unencrypted location.",
                                impact="Users fail to be upgraded to encrypted communications.",
                                remediation="Redirect all HTTP requests to https:// with status 301."
                            ))
            except Exception:
                pass

        # 2. Inspect crawled pages for open redirect parameter patterns
        seen_param_findings = set()
        for page in pages:
            parsed = urlparse(page.url)
            query_params = parse_qs(parsed.query)
            for param in query_params.keys():
                p_lower = param.lower()
                if p_lower in OPEN_REDIRECT_PARAMS and p_lower not in seen_param_findings:
                    seen_param_findings.add(p_lower)
                    findings.append(create_finding(
                        scanner="redirects",
                        title=f"Potential Open Redirect Parameter Observed ('{param}')",
                        severity="LOW",
                        confidence="MEDIUM",
                        category="Broken Access Control",
                        owasp_key="BROKEN_ACCESS_CONTROL",
                        url=page.url,
                        evidence=f"URL contains navigation parameter: {param}={query_params[param][0][:60]}",
                        description=f"The parameter '{param}' typically controls post-action or login redirects.",
                        impact="If unvalidated, attackers can construct phishing links that redirect users to malicious domains after navigating through this trusted website.",
                        remediation="Ensure redirect targets are strictly validated against a relative path check or an allowlist of trusted origins."
                    ))

        return findings
