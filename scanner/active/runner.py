"""
NayVista Shield - Active Security Assessment Runner
Coordinates all 14 active security validation modules under strict safety governance.
"""

import time
import asyncio
from typing import Dict, Any, List, Optional, Callable
from scanner.active.scope_policy import ScopePolicy
from scanner.active.controller import ActiveRequestController
from scanner.active.modules.recon import ReconDiscoveryModule
from scanner.active.modules.network import NetworkServiceValidationModule
from scanner.active.modules.tls import TLSValidationModule
from scanner.active.modules.http_security import HTTPSecurityValidationModule
from scanner.active.modules.cookies import CookieSessionValidationModule
from scanner.active.modules.endpoint_discovery import WebEndpointDiscoveryModule
from scanner.active.modules.api_security import APISecurityValidationModule
from scanner.active.modules.auth_review import AuthenticationReviewModule
from scanner.active.modules.access_control import AccessControlConsistencyModule
from scanner.active.modules.cors import CORSValidationModule
from scanner.active.modules.infrastructure import InfrastructureExposureModule
from scanner.active.modules.information import InformationExposureModule
from scanner.active.modules.http_behavior import HTTPBehaviorValidationModule
from scanner.active.modules.correlation import CorrelationModule
from scanner.scoring import calculate_security_score

ProgressCallback = Callable[[str, str, int, int, Optional[Dict[str, Any]]], None]

class ActiveScanRunner:
    def __init__(
        self,
        target_url: str,
        authorized: bool = False,
        allow_local: bool = False,
        scope_manifest: Optional[Dict[str, Any]] = None,
        selected_modules: Optional[List[str]] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_activity: Optional[Callable[[str], None]] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ):
        if not authorized:
            raise PermissionError("Active / Authorized Testing requires explicit authorization confirmation.")

        self.target_url = target_url
        self.authorized = authorized
        self.allow_local = allow_local
        self.scope_manifest = scope_manifest or {}
        self.selected_modules = selected_modules
        self.on_progress = on_progress
        self.on_activity = on_activity
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

    async def run_async(self) -> Dict[str, Any]:
        t0 = time.time()
        all_findings: List[Dict[str, Any]] = []
        is_limited = False
        limitations: List[Dict[str, Any]] = []

        stage_status: Dict[str, str] = {
            "Scope Policy": "PENDING",
            "DNS Resolution": "PENDING",
            "Recon & Discovery": "PENDING",
            "Network Validation": "PENDING",
            "TLS Validation": "PENDING",
            "HTTP Security": "PENDING",
            "Cookie Security": "PENDING",
            "Endpoint Discovery": "PENDING",
            "API Security": "PENDING",
            "Authentication Review": "PENDING",
            "Access Control": "PENDING",
            "CORS Validation": "PENDING",
            "Infrastructure Exposure": "PENDING",
            "Information & Behavior": "PENDING",
        }

        # Step 1: Scope Policy Initialization
        self._emit("scope", "Active scope policy initialization", 1, 14)
        allowed_hosts = self.scope_manifest.get("allowed_hosts")
        excluded_paths = self.scope_manifest.get("excluded_paths")
        scope_policy = ScopePolicy(
            self.target_url,
            allowed_hosts=allowed_hosts,
            excluded_paths=excluded_paths,
            allow_local=self.allow_local,
        )
        stage_status["Scope Policy"] = "COMPLETED"

        controller = ActiveRequestController(
            scope_policy=scope_policy,
            max_concurrency=4,
            max_total_requests=100,
            max_stage_requests=20,
            cancel_event=self.cancel_event,
            on_activity=self._activity,
        )

        scope = scope_policy.target_scope
        context: Dict[str, Any] = {}

        try:
            # Step 2: DNS & Network Reachability Check
            self._emit("dns", "DNS and address resolution", 2, 14, stats={"resolved_ipv4": scope.resolved_ipv4})
            if scope.dns_status == "SUCCESS":
                self._activity(f"Active DNS resolved: {scope.hostname} -> IPv4: {scope.resolved_ipv4 or 'N/A'}")
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
                self._activity(f"DNS resolution failed: {scope.dns_error}")

            if scope.dns_status != "SUCCESS":
                # Skip subsequent active stages when DNS resolution fails
                for st in stage_status:
                    if stage_status[st] == "PENDING":
                        stage_status[st] = "SKIPPED"
                posture = "LIMITED"
                assessment_status = "COMPLETED_WITH_LIMITATIONS"
            else:
                # Step 3: Recon & Discovery
                self._emit("recon", "Active reconnaissance & method discovery", 3, 14)
                self._activity("Probing HTTP OPTIONS and safe discovery manifests (robots.txt, security.txt)")
                recon_mod = ReconDiscoveryModule()
                recon_findings = await recon_mod.execute(controller, context)
                all_findings.extend(recon_findings)
                stage_status["Recon & Discovery"] = "COMPLETED"

                # Step 4: Network Validation
                self._emit("network", "Network service exposure validation", 4, 14)
                self._activity("Auditing curated network service exposure on target host")
                net_mod = NetworkServiceValidationModule()
                net_findings = await net_mod.execute(controller, context)
                all_findings.extend(net_findings)
                stage_status["Network Validation"] = "COMPLETED"

                # Step 5: TLS Validation
                self._emit("tls", "TLS cryptographic validation", 5, 14)
                self._activity("Validating SSL/TLS handshake, cipher strength, and certificates")
                tls_mod = TLSValidationModule()
                tls_findings = await tls_mod.execute(controller, context)
                all_findings.extend(tls_findings)
                stage_status["TLS Validation"] = "COMPLETED"

                # Step 6: HTTP Security Validation
                self._emit("http_security", "HTTP security header validation", 6, 14)
                self._activity("Analyzing defense headers (HSTS, CSP, XFO, nosniff, technology disclosures)")
                http_sec_mod = HTTPSecurityValidationModule()
                http_sec_findings = await http_sec_mod.execute(controller, context)
                all_findings.extend(http_sec_findings)
                stage_status["HTTP Security"] = "COMPLETED"

                # Step 7: Cookie Security Validation
                self._emit("cookies", "Cookie and session validation", 7, 14)
                self._activity("Validating Set-Cookie directives and session token hygiene")
                cookie_mod = CookieSessionValidationModule()
                cookie_findings = await cookie_mod.execute(controller, context)
                all_findings.extend(cookie_findings)
                stage_status["Cookie Security"] = "COMPLETED"

                # Step 8: Endpoint Discovery
                self._emit("endpoint_discovery", "Active web endpoint discovery", 8, 14)
                self._activity("Conducting bounded discovery of administrative and API endpoints")
                discovery_mod = WebEndpointDiscoveryModule()
                disc_findings = await discovery_mod.execute(controller, context)
                all_findings.extend(disc_findings)
                stage_status["Endpoint Discovery"] = "COMPLETED"

                # Step 9: API Security Validation
                self._emit("api_security", "API security validation", 9, 14)
                self._activity("Inspecting discovered API schemas and unauthenticated JSON disclosures")
                api_mod = APISecurityValidationModule()
                api_findings = await api_mod.execute(controller, context)
                all_findings.extend(api_findings)
                stage_status["API Security"] = "COMPLETED"

                # Step 10: Authentication Review
                self._emit("auth_review", "Authentication configuration review", 10, 14)
                self._activity("Auditing authentication form transport hygiene and password protection")
                auth_mod = AuthenticationReviewModule()
                auth_findings = await auth_mod.execute(controller, context)
                all_findings.extend(auth_findings)
                stage_status["Authentication Review"] = "COMPLETED"

                # Step 11: Access Control Consistency
                self._emit("access_control", "Access-control consistency validation", 11, 14)
                self._activity("Validating unauthenticated access barriers on administrative interfaces")
                ac_mod = AccessControlConsistencyModule()
                ac_findings = await ac_mod.execute(controller, context)
                all_findings.extend(ac_findings)
                stage_status["Access Control"] = "COMPLETED"

                # Step 12: CORS Validation
                self._emit("cors", "CORS policy validation", 12, 14)
                self._activity("Probing CORS reflection and credential exposure policies")
                cors_mod = CORSValidationModule()
                cors_findings = await cors_mod.execute(controller, context)
                all_findings.extend(cors_findings)
                stage_status["CORS Validation"] = "COMPLETED"

                # Step 13: Infrastructure Exposure
                self._emit("infrastructure", "Infrastructure exposure validation", 13, 14)
                self._activity("Probing for exposed Git repositories, .env files, and configuration leaks")
                infra_mod = InfrastructureExposureModule()
                infra_findings = await infra_mod.execute(controller, context)
                all_findings.extend(infra_findings)
                stage_status["Infrastructure Exposure"] = "COMPLETED"

                # Step 14: Information Exposure & HTTP Behavior
                self._emit("behavior", "Information exposure & HTTP behavior validation", 14, 14)
                self._activity("Checking for leaked secrets, API keys, HTTP verb tampering, and open redirects")
                info_mod = InformationExposureModule()
                info_findings = await info_mod.execute(controller, context)
                all_findings.extend(info_findings)

                behavior_mod = HTTPBehaviorValidationModule()
                behavior_findings = await behavior_mod.execute(controller, context)
                all_findings.extend(behavior_findings)
                stage_status["Information & Behavior"] = "COMPLETED"

                # Merge any controller rate limit limitations
                if controller.limitations:
                    is_limited = True
                    limitations.extend(controller.limitations)

                posture = "ASSESSED" if not is_limited else "RESTRICTED"
                assessment_status = "COMPLETED" if not is_limited else "COMPLETED_WITH_LIMITATIONS"

        finally:
            await controller.close()

        # Correlate findings
        correlator = CorrelationModule()
        final_findings = correlator.correlate(all_findings, target_url=self.target_url)

        completed_stages = sum(1 for s in stage_status.values() if s == "COMPLETED")
        coverage_percentage = int(round((completed_stages / 14.0) * 100))

        scoring_data = calculate_security_score(final_findings, posture=posture, coverage=coverage_percentage)

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
            "assessment_scope": "Active / Authorized Testing (Comprehensive)" if assessment_status == "COMPLETED" else "Active / Authorized Testing (With Limitations)",
            "status": assessment_status,
        }

        primary_ip = scope.resolved_ipv4 or (scope.all_ips[0] if scope.all_ips else "Not resolved")

        discovered = sorted(list(context.get("discovered_endpoints", set())))
        if not discovered:
            discovered = [self.target_url]

        inventory_data = {
            "total_pages": controller.total_requests_made,
            "endpoints": discovered,
            "parameters": [],
            "forms_count": len(context.get("login_forms", [])),
            "forms": context.get("login_forms", []),
            "api_endpoints": context.get("api_endpoints", []),
        }

        tech_data = {
            "web_servers": context.get("detected_servers", []),
            "backend": context.get("detected_backend", []),
            "cms": [],
            "frontend": [],
            "libraries": [],
        }

        return {
            "target": self.target_url,
            "normalized_target": scope.normalized_target,
            "hostname": scope.hostname,
            "port": scope.port,
            "scheme": scope.scheme,
            "mode": "ACTIVE / AUTHORIZED TESTING",
            "assessment_status": assessment_status,
            "is_limited": is_limited,
            "resolved_ip": primary_ip,
            "dns": dns_info,
            "network_exposure": context.get("network_exposure", []),
            "coverage": coverage_data,
            "stage_status": stage_status,
            "limitations": limitations,
            "posture": posture,
            "pages_scanned": controller.total_requests_made,
            "duration_seconds": duration_sec,
            "scoring": scoring_data,
            "findings": final_findings,
            "requests_made": controller.total_requests_made,
            "stage_requests": controller.stage_requests_made,
            "active_modules_executed": 14,
            "inventory": inventory_data,
            "technologies": tech_data,
        }
