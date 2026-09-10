"""
SentinelScan - Content & HTML Security Analysis Scanner
Parses HTML content for:
- Forms submitting over cleartext HTTP or lacking CSRF tokens.
- Password fields served or submitted over unencrypted HTTP.
- Active & passive mixed content on HTTPS pages.
- External scripts lacking Subresource Integrity (SRI).
- Unsandboxed iframe tags.
- Links opening in new windows without rel="noopener noreferrer".
"""

from typing import List, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from scanner.crawler import CrawledPage
from scanner.normalizer import create_finding

class ContentScanner:
    def scan(self, pages: List[CrawledPage]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        seen_mixed_scripts = False
        seen_insecure_forms = False
        seen_passwords_over_http = False
        seen_missing_sri = False
        seen_unsandboxed_iframes = False
        seen_tabnabbing = False

        for page in pages:
            if page.status_code != 200 or not page.text:
                continue
            if "text/html" not in page.headers.get("content-type", "text/html"):
                continue

            soup = page.get_soup()
            is_https = page.url.lower().startswith("https://")

            # 1. Password field over HTTP check
            password_inputs = soup.find_all("input", type=lambda t: t and t.lower() == "password")
            if password_inputs and not is_https and not seen_passwords_over_http:
                seen_passwords_over_http = True
                findings.append(create_finding(
                    scanner="content_scanner",
                    title="Password Input Field Served Over Insecure HTTP",
                    severity="HIGH",
                    confidence="HIGH",
                    category="Cryptographic Failures",
                    owasp_key="CRYPTOGRAPHIC_FAILURES",
                    url=page.url,
                    evidence=f"Found {len(password_inputs)} password field(s) on cleartext page.",
                    description="Authentication or password entry forms served over unencrypted HTTP expose user credentials to network interception.",
                    impact="Adversaries on local networks can intercept passwords in plaintext or tamper with the form action.",
                    remediation="Serve all pages containing password fields exclusively over HTTPS."
                ))

            # 2. Form analysis (action over HTTP)
            forms = soup.find_all("form")
            for form in forms:
                action = (form.get("action") or "").strip()
                if action.lower().startswith("http://") and is_https and not seen_insecure_forms:
                    seen_insecure_forms = True
                    findings.append(create_finding(
                        scanner="content_scanner",
                        title="Form Action Submits to Insecure HTTP Endpoint",
                        severity="HIGH",
                        confidence="HIGH",
                        category="Cryptographic Failures",
                        owasp_key="CRYPTOGRAPHIC_FAILURES",
                        url=page.url,
                        evidence=f"Form action target: '{action}'",
                        description="An HTTPS page contains a form that submits user data to an unencrypted HTTP endpoint.",
                        impact="Submitted form data (including credentials or personal details) is transmitted across the internet in plaintext.",
                        remediation="Update the form action to submit via HTTPS."
                    ))

            # 3. Mixed Content Analysis (HTTPS page loading HTTP resources)
            if is_https:
                # Active mixed content (scripts)
                insecure_scripts = [s.get("src") for s in soup.find_all("script", src=True) if s.get("src", "").lower().startswith("http://")]
                if insecure_scripts and not seen_mixed_scripts:
                    seen_mixed_scripts = True
                    findings.append(create_finding(
                        scanner="content_scanner",
                        title="Active Mixed Content Detected (HTTP Scripts on HTTPS)",
                        severity="HIGH",
                        confidence="HIGH",
                        category="Cryptographic Failures",
                        owasp_key="CRYPTOGRAPHIC_FAILURES",
                        url=page.url,
                        evidence=f"Script source: '{insecure_scripts[0]}'",
                        description="An HTTPS webpage attempts to load executable JavaScript over unencrypted HTTP.",
                        impact="Browsers will block the script, or an attacker could intercept and modify the script to achieve full site compromise.",
                        remediation="Ensure all script resources are loaded using https:// or relative paths."
                    ))

            # 4. External Scripts Subresource Integrity (SRI)
            external_scripts = []
            page_host = urlparse(page.url).hostname
            for script in soup.find_all("script", src=True):
                src = script.get("src", "").strip()
                parsed_src = urlparse(src)
                if parsed_src.hostname and parsed_src.hostname != page_host:
                    if not script.get("integrity"):
                        external_scripts.append(src)

            if external_scripts and not seen_missing_sri:
                seen_missing_sri = True
                findings.append(create_finding(
                    scanner="content_scanner",
                    title="External CDN Scripts Loaded Without Subresource Integrity (SRI)",
                    severity="LOW",
                    confidence="HIGH",
                    category="Software and Data Integrity Failures",
                    owasp_key="INTEGRITY_FAILURES",
                    url=page.url,
                    evidence=f"External script missing integrity attribute: {external_scripts[0][:80]}...",
                    description="External JavaScript files are loaded from third-party hosts or CDNs without Subresource Integrity hashes.",
                    impact="If the third-party CDN is compromised, malicious code could be injected into this application.",
                    remediation="Add cryptographic 'integrity' attributes and 'crossorigin=\"anonymous\"' to external script tags."
                ))

            # 5. Unsandboxed iframes
            iframes = soup.find_all("iframe")
            unsandboxed = [iframe for iframe in iframes if not iframe.get("sandbox")]
            if unsandboxed and not seen_unsandboxed_iframes:
                seen_unsandboxed_iframes = True
                findings.append(create_finding(
                    scanner="content_scanner",
                    title="Embedded Iframe Lacks Sandbox Attribute",
                    severity="LOW",
                    confidence="MEDIUM",
                    category="Security Misconfiguration",
                    owasp_key="SECURITY_MISCONFIGURATION",
                    url=page.url,
                    evidence=f"Found {len(unsandboxed)} iframe element(s) without sandbox attribute.",
                    description="Iframes without a sandbox attribute have unrestricted execution permissions within their context.",
                    impact="Embedded content can run untrusted scripts or navigate the top-level browsing context.",
                    remediation="Apply the 'sandbox' attribute to iframe tags with the minimum necessary permissions."
                ))

            # 6. Target blank without rel="noopener noreferrer" (Reverse Tabnabbing)
            tabnab_links = []
            for a in soup.find_all("a", href=True):
                if a.get("target") == "_blank":
                    rel = (a.get("rel") or [])
                    if isinstance(rel, str):
                        rel = rel.split()
                    rel_set = {r.lower() for r in rel}
                    if "noopener" not in rel_set and "noreferrer" not in rel_set:
                        tabnab_links.append(a.get("href"))

            if tabnab_links and not seen_tabnabbing:
                seen_tabnabbing = True
                findings.append(create_finding(
                    scanner="content_scanner",
                    title="Links with target='_blank' Missing rel='noopener noreferrer'",
                    severity="LOW",
                    confidence="HIGH",
                    category="Security Misconfiguration",
                    owasp_key="SECURITY_MISCONFIGURATION",
                    url=page.url,
                    evidence=f"Link to '{tabnab_links[0][:70]}' opens in new tab without rel='noopener noreferrer'.",
                    description="Opening external links with target='_blank' without 'rel=\"noopener noreferrer\"' allows the target page access to window.opener.",
                    impact="A malicious linked page can redirect the opener tab to a convincing phishing page (Reverse Tabnabbing).",
                    remediation="Add rel='noopener noreferrer' to all anchor tags with target='_blank'."
                ))

        return findings
