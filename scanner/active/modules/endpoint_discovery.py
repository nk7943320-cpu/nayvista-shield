"""
NayVista Shield - Active Web Endpoint Discovery Module
Performs bounded, non-destructive discovery of standard administrative and sensitive endpoints.
"""

from typing import Dict, Any, List, Set
from urllib.parse import urljoin
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

DISCOVERY_CANDIDATES = [
    "/admin",
    "/administrator",
    "/login",
    "/signin",
    "/dashboard",
    "/api",
    "/api/v1",
    "/api/v2",
    "/metrics",
    "/health",
    "/status",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
]

class WebEndpointDiscoveryModule(ActiveModule):
    name = "WebEndpointDiscovery"
    description = "Bounded discovery of standard administrative, API, and status endpoints"
    stage_name = "Endpoint Discovery"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Endpoint Discovery")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        discovered_endpoints: Set[str] = context.setdefault("discovered_endpoints", set())
        admin_endpoints: List[str] = context.setdefault("admin_endpoints", [])
        api_endpoints: List[str] = context.setdefault("api_endpoints", [])

        for candidate_path in DISCOVERY_CANDIDATES:
            cand_url = urljoin(target, candidate_path)
            resp = await controller.request("GET", cand_url)
            if not resp:
                continue

            # Record successfully responding endpoints
            if resp.status_code in (200, 301, 302, 401, 403):
                discovered_endpoints.add(cand_url)

            if resp.status_code == 200:
                if any(p in candidate_path for p in ("/admin", "/administrator", "/dashboard")):
                    admin_endpoints.append(cand_url)
                elif any(p in candidate_path for p in ("/api", "/swagger", "/openapi", "/api-docs")):
                    api_endpoints.append(cand_url)
                elif candidate_path in ("/metrics", "/health"):
                    # Check if /metrics reveals internal Prometheus / runtime data
                    if "jvm_" in resp.text or "go_goroutines" in resp.text or "process_cpu_seconds" in resp.text:
                        findings.append(self.create_finding(
                            title="Publicly Accessible Prometheus Metrics Endpoint",
                            severity="MEDIUM",
                            confidence="CONFIRMED",
                            owasp="A05:2021-Security Misconfiguration",
                            cwe="CWE-200",
                            description=f"Internal application runtime metrics are publicly exposed at {cand_url} without authentication.",
                            impact="Metrics reveal detailed server topology, memory usage, traffic volume, and internal process stats to external adversaries.",
                            remediation="Restrict access to metrics and health monitoring endpoints via network firewalls or authentication middleware.",
                            target_url=target,
                            endpoint=cand_url,
                            test_performed=f"GET {candidate_path} retrieval and content inspection",
                            expected="HTTP 401/403 or internal network restriction",
                            observed=f"HTTP 200 with runtime metrics exposed ({len(resp.text)} bytes)",
                            raw_evidence=f"Content sample: {resp.text[:150]}",
                        ))

        return findings
