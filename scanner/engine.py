"""
NayVista Shield - Core Scanning Engine
Reusable, programmatic scanning engine shared by Web GUI and Terminal CLI.
"""

import sys
import json
import time
import asyncio
from typing import Dict, Any, Callable, Optional
from scanner.scope import TargetScope
from scanner.crawler import SafeCrawler
from scanner.findings import deduplicate_findings
from scanner.scoring import calculate_security_score
from scanner.modules.headers import HeadersScanner
from scanner.modules.cookies import CookieScanner
from scanner.modules.tls import TLSScanner
from scanner.modules.cors import CORSScanner
from scanner.modules.information import InfoDisclosureScanner
from scanner.modules.methods import HTTPMethodsScanner
from scanner.modules.redirects import RedirectScanner
from scanner.modules.content import ContentScanner
from scanner.modules.surface import SurfaceInventoryScanner
from scanner.modules.technology import TechDetector
from scanner.modules.network_exposure import NetworkExposureScanner
from scanner.config import MAX_PAGES, MAX_DEPTH

class ScanExecutionError(RuntimeError):
    """Raised when the assessment cannot proceed due to unreachable host or network failure."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

ProgressCallback = Callable[[str, str, int, int, Optional[Dict[str, Any]]], None]

class ScannerEngine:
    def __init__(
        self,
        target_url: str,
        allow_local: bool = False,
        on_progress: Optional[ProgressCallback] = None,
        on_activity: Optional[Callable[[str], None]] = None,
        mode: str = "DEFENSIVE / SAFE",
        authorized: bool = False,
        scope_manifest: Optional[Dict[str, Any]] = None,
        selected_modules: Optional[List[str]] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ):
        self.target_url = target_url
        self.allow_local = allow_local
        self.on_progress = on_progress
        self.on_activity = on_activity
        self.mode = mode.upper() if mode else "DEFENSIVE / SAFE"
        self.authorized = authorized
        self.scope_manifest = scope_manifest or {}
        self.selected_modules = selected_modules
        self.cancel_event = cancel_event

    def _activity(self, message: str):
        if self.on_activity:
            try:
                self.on_activity(message)
            except Exception:
                pass

    def _emit(self, phase: str, message: str, step: int, total_steps: int = 14, stats: Optional[Dict[str, Any]] = None):
        if self.on_progress:
            try:
                self.on_progress(phase, message, step, total_steps, stats or {})
            except Exception:
                pass

    async def scan_async(self) -> Dict[str, Any]:
        # Branch to Active / Authorized Testing runner if requested
        if "ACTIVE" in self.mode or "AUTHORIZED" in self.mode:
            from scanner.active.runner import ActiveScanRunner
            runner = ActiveScanRunner(
                target_url=self.target_url,
                authorized=self.authorized,
                allow_local=self.allow_local,
                scope_manifest=self.scope_manifest,
                selected_modules=self.selected_modules,
                on_progress=self.on_progress,
                on_activity=self.on_activity,
                cancel_event=self.cancel_event,
            )
            return await runner.run_async()

        t0 = time.time()
        all_raw_findings = []
        is_limited = False
        limitations: List[Dict[str, Any]] = []

        stage_status: Dict[str, str] = {
            "Target Validation": "PENDING",
            "DNS Resolution": "PENDING",
            "Scope Validation": "PENDING",
            "IP Exposure": "PENDING",
            "Port Exposure": "PENDING",
            "HTTP Security": "PENDING",
            "TLS Analysis": "PENDING",
            "Cookie Security": "PENDING",
            "Web Crawling": "PENDING",
            "Information Exposure": "PENDING",
            "Infrastructure Exposure": "PENDING",
            "Finding Correlation": "PENDING",
            "Security Posture": "PENDING",
            "Report Generation": "PENDING",
        }

        # Stage 1: TARGET VALIDATION
        self._emit("validation", "Target validation", 1, 14)
        self._activity(f"Validating target URL syntax and protocol: {self.target_url}")
        scope = TargetScope(self.target_url, allow_local=self.allow_local, raise_on_dns_failure=False)
        stage_status["Target Validation"] = "COMPLETED"

        # Stage 2: DNS RESOLUTION
        self._emit("dns", "DNS resolution", 2, 14, stats={"resolved_ipv4": scope.resolved_ipv4, "resolved_ipv6": scope.resolved_ipv6})
        if scope.dns_status == "SUCCESS":
            self._activity(f"DNS resolved: {scope.hostname} -> IPv4: {scope.resolved_ipv4 or 'N/A'}, IPv6: {scope.resolved_ipv6 or 'Not detected'}")
            stage_status["DNS Resolution"] = "COMPLETED"
        else:
            is_limited = True
            stage_status["DNS Resolution"] = "FAILED"
            limitations.append({
                "stage": "DNS Resolution",
                "status": "FAILED",
                "code": "TARGET_DNS_FAILURE",
                "category": "ASSESSMENT_LIMITATION",
                "reason": scope.dns_error or f"Hostname '{scope.hostname}' could not be resolved via DNS.",
            })
            self._activity(f"DNS resolution failed for hostname '{scope.hostname}': {scope.dns_error}")

        # Stage 3: SCOPE VALIDATION
        self._emit("scope", "Scope validation", 3, 14)
        if scope.dns_status != "SUCCESS":
            stage_status["Scope Validation"] = "SKIPPED"
            limitations.append({
                "stage": "Scope Validation",
                "status": "SKIPPED",
                "code": "NO_RESOLVED_TARGET_IP",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Scope validation skipped because target hostname could not be resolved.",
            })
        else:
            self._activity(f"Target scope verified: {scope.normalized_target} (same-origin boundaries active)")
            stage_status["Scope Validation"] = "COMPLETED"

        # Stage 4: IP EXPOSURE
        self._emit("ip_exposure", "IP exposure analysis", 4, 14)
        if scope.dns_status != "SUCCESS" or (not scope.resolved_ipv4 and not scope.all_ips):
            primary_ip = "Not resolved"
            stage_status["IP Exposure"] = "SKIPPED"
            limitations.append({
                "stage": "IP Exposure",
                "status": "SKIPPED",
                "code": "NO_RESOLVED_TARGET_IP",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "IP exposure analysis skipped because no target IP was resolved.",
            })
        else:
            primary_ip = scope.resolved_ipv4 or (scope.all_ips[0] if scope.all_ips else "N/A")
            self._activity(f"Target address exposure: {primary_ip} ({len(scope.all_ips)} record(s) resolved)")
            stage_status["IP Exposure"] = "COMPLETED"

        # Stage 5: PORT EXPOSURE
        self._emit("port_exposure", "Network port exposure", 5, 14)
        if scope.dns_status != "SUCCESS" or (not scope.resolved_ipv4 and not scope.all_ips):
            exposure_entries = []
            stage_status["Port Exposure"] = "SKIPPED"
            limitations.append({
                "stage": "Port Exposure",
                "status": "SKIPPED",
                "code": "NO_RESOLVED_TARGET_IP",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Port exposure assessment requires a successfully resolved and permitted target IP.",
            })
            self._activity("Port exposure probe skipped: No successfully resolved target IP.")
        else:
            self._activity(f"Probing curated standard service ports on {scope.hostname}...")
            port_scanner = NetworkExposureScanner()
            exposure_entries, port_findings = await port_scanner.scan_async(scope)
            all_raw_findings.extend(port_findings)
            if port_scanner.status == "SKIPPED":
                stage_status["Port Exposure"] = "SKIPPED"
                if port_scanner.limitation:
                    limitations.append(port_scanner.limitation)
            elif port_scanner.status == "LIMITED":
                is_limited = True
                stage_status["Port Exposure"] = "LIMITED"
                if port_scanner.limitation:
                    limitations.append(port_scanner.limitation)
            else:
                stage_status["Port Exposure"] = "COMPLETED"
            open_ports = [e["port"] for e in exposure_entries if e["state"] == "OPEN"]
            self._activity(f"Port exposure probe complete: {len(open_ports)} open port(s) detected ({', '.join(map(str, open_ports)) if open_ports else 'none'})")

        # Stage 6: HTTP SECURITY
        self._emit("headers", "HTTP security analysis", 6, 14)
        initial_pages = []
        crawler = None

        if scope.dns_status != "SUCCESS":
            stage_status["HTTP Security"] = "LIMITED"
            limitations.append({
                "stage": "HTTP Security",
                "status": "LIMITED",
                "code": "TARGET_DNS_FAILURE",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "HTTP security inspection could not connect because hostname could not be resolved.",
            })
        else:
            self._activity(f"Establishing baseline HTTP connection to {scope.normalized_target}")
            crawler = SafeCrawler(scope=scope, max_pages=MAX_PAGES, max_depth=MAX_DEPTH, on_activity=self._activity)
            initial_pages = await crawler.fetch_root()

            if not initial_pages:
                is_limited = True
                stage_status["HTTP Security"] = "LIMITED"
                err_code = crawler.crawl_error_code or "TARGET_UNREACHABLE"
                err_cat = crawler.crawl_error_category or "ASSESSMENT_LIMITATION"
                err_msg = crawler.crawl_error or f"Target '{self.target_url}' could not be reached within configured timeout."
                limitations.append({
                    "stage": "HTTP Security",
                    "status": "LIMITED",
                    "code": err_code,
                    "category": err_cat,
                    "reason": err_msg,
                })
                self._activity(f"Assessment limitation: HTTP security inspection limited ({err_msg})")
            else:
                stage_status["HTTP Security"] = "COMPLETED"
                headers_scanner = HeadersScanner()
                header_findings = headers_scanner.scan(initial_pages)
                all_raw_findings.extend(header_findings)

        # Stage 7: TLS ANALYSIS
        self._emit("tls", "HTTPS/TLS analysis", 7, 14)
        if scope.dns_status != "SUCCESS" or (crawler and not initial_pages and crawler.crawl_error_code in ("TARGET_TIMEOUT", "TARGET_CONNECTION_REFUSED", "TARGET_UNREACHABLE")):
            stage_status["TLS Analysis"] = "LIMITED"
            limitations.append({
                "stage": "TLS Analysis",
                "status": "LIMITED",
                "code": "TARGET_UNREACHABLE",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "TLS inspection could not establish a connection to target host.",
            })
        else:
            self._activity("Inspecting SSL/TLS certificate and cipher suites")
            tls_scanner = TLSScanner()
            tls_findings = tls_scanner.scan(scope)
            all_raw_findings.extend(tls_findings)
            stage_status["TLS Analysis"] = "COMPLETED"
            self._activity(f"TLS inspection complete: {len(tls_findings)} observation(s)")

            if crawler and crawler.tls_verification_failed:
                all_raw_findings.append({
                    "id": "tls-cert-verification-failed",
                    "scanner": "SafeCrawler",
                    "title": "TLS Certificate Verification Failed",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "owasp": "A02:2021-Cryptographic Failures",
                    "cwe": "CWE-295",
                    "description": "The TLS certificate presented by the target failed standard cryptographic validation (expired, self-signed, untrusted issuer, or hostname mismatch). The crawler fell back to passive unverified inspection solely to audit defensive HTTP headers and configurations.",
                    "evidence": f"Certificate validation error on target '{scope.normalized_target}'.",
                    "impact": "Users navigating to the site will receive browser security warnings or be susceptible to Man-In-The-Middle (MITM) interception.",
                    "remediation": "Deploy a valid, unexpired TLS certificate issued by a recognized Certificate Authority (e.g., Let's Encrypt, DigiCert) matching the canonical hostname.",
                    "url": scope.normalized_target,
                })

        # Add operational diagnostics if edge protection or server error encountered
        if crawler and crawler.waf_or_blocked:
            all_raw_findings.append({
                "id": "waf-protection-detected",
                "scanner": "SafeCrawler",
                "title": "Web Application Firewall (WAF) or Bot Protection Active",
                "severity": "INFO",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-693",
                "description": "The target returned HTTP 403 Forbidden to automated inspection. A Web Application Firewall (WAF) or edge CDN security rule (such as Cloudflare, AWS WAF, or Akamai) is active.",
                "evidence": f"Initial probe to '{scope.normalized_target}' received HTTP 403 Forbidden.",
                "impact": "Automated security assessment crawler was restricted from enumerating subpages.",
                "remediation": "For an exhaustive authorized assessment, add the scanner IP to the WAF allowlist or provide authorization headers.",
                "url": scope.normalized_target,
            })
        elif crawler and crawler.rate_limited:
            all_raw_findings.append({
                "id": "rate-limiting-detected",
                "scanner": "SafeCrawler",
                "title": "Origin Rate Limiting Detected (HTTP 429)",
                "severity": "INFO",
                "owasp": "A04:2021-Insecure Design",
                "cwe": "CWE-799",
                "description": "The target returned HTTP 429 Too Many Requests. Rate limiting controls are actively throttling request volume.",
                "evidence": f"Request to '{scope.normalized_target}' received HTTP 429 Too Many Requests.",
                "impact": "Crawler throughput throttled to respect origin rate limits.",
                "remediation": "Verify rate limits are tuned appropriately for legitimate user traffic and API consumers.",
                "url": scope.normalized_target,
            })
        elif crawler and crawler.server_error:
            all_raw_findings.append({
                "id": "server-error-5xx",
                "scanner": "SafeCrawler",
                "title": "Target Server Error Response (HTTP 5xx)",
                "severity": "LOW",
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-754",
                "description": f"The target returned HTTP {crawler.initial_status_code} during initial probe. This indicates an unhandled server condition or upstream proxy error.",
                "evidence": f"HTTP status code: {crawler.initial_status_code}",
                "impact": "Site functionality may be impaired or leaking internal debug details.",
                "remediation": "Inspect server logs to identify and remediate the 5xx status response.",
                "url": scope.normalized_target,
            })

        # Stage 8: COOKIE SECURITY
        self._emit("cookies", "Cookie security", 8, 14)
        if not initial_pages:
            stage_status["Cookie Security"] = "LIMITED"
            limitations.append({
                "stage": "Cookie Security",
                "status": "LIMITED",
                "code": "NO_HTTP_RESPONSE",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Cookie security audit skipped because target produced no HTTP response.",
            })
        else:
            self._activity("Auditing cookie security flags (Secure, HttpOnly, SameSite)")
            cookie_scanner = CookieScanner()
            cookie_findings = cookie_scanner.scan(initial_pages)
            all_raw_findings.extend(cookie_findings)
            stage_status["Cookie Security"] = "COMPLETED"

        # Stage 9: WEB CRAWLING
        self._emit("crawling", "Web crawling", 9, 14, stats={"pages_discovered": len(crawler.pages) if crawler else 0})
        pages = []
        if not initial_pages or not crawler:
            stage_status["Web Crawling"] = "LIMITED"
            limitations.append({
                "stage": "Web Crawling",
                "status": "LIMITED",
                "code": "TARGET_UNREACHABLE",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Web crawling could not discover same-origin pages on unreachable target.",
            })
        else:
            self._activity("Crawling same-origin discovered links (conservative throttled exploration)")
            pages = await crawler.crawl_subpages()
            if crawler.crawl_budget_exceeded or crawler.rate_limited or crawler.slow_pages:
                stage_status["Web Crawling"] = "LIMITED"
                is_limited = True
                for l in crawler.limitations:
                    limitations.append(l)
            else:
                stage_status["Web Crawling"] = "COMPLETED"

            # Update headers and cookie findings if subpages were crawled
            if len(pages) > len(initial_pages):
                more_pages = pages[len(initial_pages):]
                headers_scanner = HeadersScanner()
                cookie_scanner = CookieScanner()
                all_raw_findings.extend(headers_scanner.scan(more_pages))
                all_raw_findings.extend(cookie_scanner.scan(more_pages))

        stats = {"pages_discovered": len(pages)}

        # Stage 10: INFORMATION EXPOSURE
        self._emit("information", "Information exposure", 10, 14, stats=stats)
        if not pages:
            stage_status["Information Exposure"] = "LIMITED"
            limitations.append({
                "stage": "Information Exposure",
                "status": "LIMITED",
                "code": "NO_PAGE_CONTENT",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Information exposure scan could not analyze content from unreachable target.",
            })
        else:
            self._activity("Scanning page content for sensitive data exposure & secrets")
            info_scanner = InfoDisclosureScanner()
            info_findings = info_scanner.scan(scope, pages)
            all_raw_findings.extend(info_findings)

            content_scanner = ContentScanner()
            content_findings = content_scanner.scan(pages)
            all_raw_findings.extend(content_findings)

            if stage_status["Web Crawling"] == "LIMITED":
                stage_status["Information Exposure"] = "LIMITED"
            else:
                stage_status["Information Exposure"] = "COMPLETED"

        # Stage 11: INFRASTRUCTURE EXPOSURE
        self._emit("surface", "Infrastructure exposure", 11, 14, stats=stats)
        if not pages:
            inventory_data = {
                "total_pages": 0,
                "endpoints": [],
                "parameters": [],
                "forms_count": 0,
                "forms": [],
                "api_endpoints": [],
            }
            tech_data = {
                "web_servers": [],
                "backend": [],
                "cms": [],
                "frontend": [],
                "libraries": [],
            }
            stage_status["Infrastructure Exposure"] = "LIMITED"
            limitations.append({
                "stage": "Infrastructure Exposure",
                "status": "LIMITED",
                "code": "NO_PAGE_CONTENT",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Attack surface inventory could not be enumerated on unreachable target.",
            })
        else:
            self._activity("Auditing attack-surface endpoints, HTTP methods, and technologies")
            surface_scanner = SurfaceInventoryScanner()
            surface_findings, inventory_data = surface_scanner.scan(scope, pages)
            all_raw_findings.extend(surface_findings)

            tech_scanner = TechDetector()
            tech_findings, tech_data = tech_scanner.scan(pages)
            all_raw_findings.extend(tech_findings)

            cors_scanner = CORSScanner()
            cors_findings = cors_scanner.scan(scope, pages)
            all_raw_findings.extend(cors_findings)

            redirect_scanner = RedirectScanner()
            redirect_findings = redirect_scanner.scan(scope, pages)
            all_raw_findings.extend(redirect_findings)

            method_scanner = HTTPMethodsScanner()
            method_findings = method_scanner.scan(scope)
            all_raw_findings.extend(method_findings)

            if stage_status["Web Crawling"] == "LIMITED":
                stage_status["Infrastructure Exposure"] = "LIMITED"
            else:
                stage_status["Infrastructure Exposure"] = "COMPLETED"

        # Stage 12: FINDING CORRELATION
        self._emit("correlation", "Finding correlation", 12, 14, stats=stats)
        self._activity("Correlating and deduplicating security observations")
        deduped = deduplicate_findings(all_raw_findings)
        stage_status["Finding Correlation"] = "COMPLETED"

        # Stage 13: SECURITY POSTURE
        self._emit("scoring", "Security posture", 13, 14, stats=stats)
        self._activity("Computing security posture score and risk classification")

        completed_stages = sum(1 for s in stage_status.values() if s == "COMPLETED")
        coverage_percentage = int(round((completed_stages / 14.0) * 100))

        # Determine assessment posture and overall status
        if is_limited or not initial_pages or scope.dns_status != "SUCCESS":
            posture = "LIMITED"
            assessment_status = "COMPLETED_WITH_LIMITATIONS"
        elif crawler and (crawler.waf_or_blocked or crawler.rate_limited):
            posture = "RESTRICTED"
            assessment_status = "COMPLETED"
        elif crawler and (crawler.server_error or crawler.tls_verification_failed):
            posture = "DEGRADED"
            assessment_status = "COMPLETED"
        else:
            posture = "ASSESSED"
            assessment_status = "COMPLETED"

        scoring_data = calculate_security_score(deduped, posture=posture, coverage=coverage_percentage)
        score_display = "N/A" if scoring_data.get("score") is None else f"{scoring_data.get('score')}/100"
        self._activity(f"Assessment complete: Status {assessment_status} | Coverage {coverage_percentage}% | Score {score_display}")

        # Stage 14: REPORT GENERATION
        self._emit("report", "Report generation", 14, 14, stats=stats)
        self._activity("Compiling audit report artifact")
        stage_status["Report Generation"] = "COMPLETED"

        duration_sec = round(time.time() - t0, 2)

        dns_info = {
            "status": scope.dns_status,
            "ipv4": scope.resolved_ipv4 or "Not resolved",
            "ipv6": scope.resolved_ipv6 or "Not resolved",
            "all_ips": scope.all_ips,
        }

        coverage_data = {
            "completed_stages": completed_stages,
            "total_stages": 14,
            "percentage": coverage_percentage,
            "coverage_pct": coverage_percentage,
            "assessment_scope": "Comprehensive" if assessment_status == "COMPLETED" else "Completed with Limitations",
            "status": assessment_status,
        }

        return {
            "target": self.target_url,
            "normalized_target": scope.normalized_target,
            "hostname": scope.hostname,
            "port": scope.port,
            "scheme": scope.scheme,
            "mode": "DEFENSIVE / SAFE",
            "assessment_status": assessment_status,
            "is_limited": is_limited,
            "resolved_ip": primary_ip,
            "dns": dns_info,
            "network_exposure": exposure_entries,
            "coverage": coverage_data,
            "stage_status": stage_status,
            "limitations": limitations,
            "posture": posture,
            "pages_scanned": len(pages),
            "pages": [
                {
                    "url": p.url,
                    "status_code": p.status_code,
                    "depth": p.depth,
                    "response_time_ms": round(p.elapsed_ms, 1),
                }
                for p in pages
            ],
            "duration_seconds": duration_sec,
            "scoring": scoring_data,
            "findings": deduped,
            "inventory": inventory_data,
            "technologies": tech_data,
        }

    def scan(self) -> Dict[str, Any]:
        """Synchronous wrapper to execute the scan engine."""
        return asyncio.run(self.scan_async())

def scan(target: str, options: Optional[Dict[str, Any]] = None, on_progress: Optional[ProgressCallback] = None) -> Dict[str, Any]:
    """
    Public functional API:
    scan('https://example.com', options={'allow_local': False}, on_progress=callback)
    """
    opts = options or {}
    allow_local = opts.get("allow_local", False)
    mode = opts.get("mode", "DEFENSIVE / SAFE")
    authorized = opts.get("authorized", False)
    scope_manifest = opts.get("scope_manifest")
    selected_modules = opts.get("selected_modules")
    engine = ScannerEngine(
        target_url=target,
        allow_local=allow_local,
        on_progress=on_progress,
        mode=mode,
        authorized=authorized,
        scope_manifest=scope_manifest,
        selected_modules=selected_modules,
    )
    return engine.scan()
