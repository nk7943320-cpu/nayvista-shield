"""
NayVista Shield - Active Access-Control Consistency Validation Module
Audits administrative and restricted endpoints for unauthenticated access and method consistency.
"""

from typing import Dict, Any, List
from urllib.parse import urljoin
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

ADMIN_CANDIDATES = [
    "/admin",
    "/admin/",
    "/administrator",
    "/dashboard",
    "/manager/html",
    "/wp-admin",
]

class AccessControlConsistencyModule(ActiveModule):
    name = "AccessControlConsistency"
    description = "Active validation of unauthenticated access barriers on administrative interfaces"
    stage_name = "Access Control"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Access Control")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        endpoints_to_test = list(context.get("admin_endpoints", []))
        for p in ADMIN_CANDIDATES:
            u = urljoin(target, p)
            if u not in endpoints_to_test:
                endpoints_to_test.append(u)

        for admin_url in endpoints_to_test[:6]:
            resp = await controller.request("GET", admin_url)
            if not resp:
                continue

            # If response is 200 OK, check if it is truly an unauthenticated admin dashboard
            if resp.status_code == 200:
                lower_body = resp.text.lower()
                # Check for signs of actual admin functionality vs a login form
                is_login_page = any(w in lower_body for w in ("password", "log in", "sign in", "login form", "username"))
                admin_keywords = ["admin panel", "administration console", "dashboard", "manage users", "system settings", "phpmyadmin"]
                has_admin_content = any(k in lower_body for k in admin_keywords)

                if has_admin_content and not is_login_page:
                    findings.append(self.create_finding(
                        title="Unauthenticated Administrative Interface Access",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-306",
                        description=f"Administrative endpoint {admin_url} returned HTTP 200 OK without requiring authentication or authorization.",
                        impact="Full administrative compromise: unauthorized external entities can access management consoles without credentials.",
                        remediation="Enforce mandatory server-side authentication gates on all administrative routes.",
                        target_url=target,
                        endpoint=admin_url,
                        test_performed="Unauthenticated HTTP GET request to administrative endpoint",
                        expected="HTTP 401 Unauthorized, HTTP 403 Forbidden, or HTTP 302 redirect to login",
                        observed="HTTP 200 OK with administrative keywords identified",
                        raw_evidence=f"Status: 200, Content: {resp.text[:200]}",
                    ))

        return findings
