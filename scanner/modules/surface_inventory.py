"""
SentinelScan - Basic Input Surface Inventory Scanner
Discovers and inventories:
- URL endpoints and query parameters.
- Forms, actions, and form field types.
- API-like endpoints discovered in links and page source.
Provides a defensive attack surface catalog for security assessment.
"""

import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs
from scanner.crawler import CrawledPage
from scanner.scope import TargetScope
from scanner.normalizer import create_finding

API_PATTERN = re.compile(r'["\'](/api/[\w\-\./]+|/v\d+/[\w\-\./]+|/graphql)[\'"]')

class SurfaceInventoryScanner:
    def scan(self, scope: TargetScope, pages: List[CrawledPage]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        discovered_endpoints = set()
        discovered_params = set()
        discovered_forms = []
        discovered_api_routes = set()

        for page in pages:
            parsed = urlparse(page.url)
            discovered_endpoints.add(parsed.path or "/")

            # Query params
            for p in parse_qs(parsed.query).keys():
                discovered_params.add(p)

            if page.status_code == 200 and page.text:
                soup = page.get_soup()

                # Forms and fields
                for form in soup.find_all("form"):
                    action = form.get("action") or parsed.path or "/"
                    method = (form.get("method") or "GET").upper()
                    fields = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        fname = inp.get("name")
                        ftype = inp.get("type", "text") if inp.name == "input" else inp.name
                        if fname:
                            fields.append({"name": fname, "type": ftype})
                            discovered_params.add(fname)

                    discovered_forms.append({
                        "page_url": page.url,
                        "action": action,
                        "method": method,
                        "fields": fields
                    })

                # Search text for API routes
                for match in API_PATTERN.findall(page.text):
                    if scope.is_same_origin(f"{scope.scheme}://{scope.hostname}:{scope.port}{match}"):
                        discovered_api_routes.add(match)

        inventory_data = {
            "total_pages": len(pages),
            "endpoints": sorted(list(discovered_endpoints)),
            "parameters": sorted(list(discovered_params)),
            "forms_count": len(discovered_forms),
            "forms": discovered_forms[:20], # cap to reasonable display size
            "api_endpoints": sorted(list(discovered_api_routes)),
        }

        # Produce Informational finding
        summary_evidence = (
            f"Cataloged {len(discovered_endpoints)} unique path(s), "
            f"{len(discovered_params)} input parameter(s), "
            f"{len(discovered_forms)} form(s), and "
            f"{len(discovered_api_routes)} API route(s)."
        )

        findings.append(create_finding(
            scanner="surface_inventory",
            title="Attack Surface Inventory Cataloged",
            severity="INFO",
            confidence="HIGH",
            category="Security Misconfiguration",
            owasp_key="SECURITY_MISCONFIGURATION",
            url=f"{scope.scheme}://{scope.hostname}:{scope.port}/",
            evidence=summary_evidence,
            description="A non-destructive structural map of accessible endpoints, input fields, forms, and API routes was assembled.",
            impact="Defines the entry points that require rigorous server-side input validation and authorization checks.",
            remediation="Ensure every cataloged parameter and API endpoint enforces strict type validation, parameter length boundaries, and access control."
        ))

        return findings, inventory_data
