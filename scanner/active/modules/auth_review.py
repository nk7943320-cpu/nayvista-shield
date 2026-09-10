"""
NayVista Shield - Active Authentication Configuration Review Module
Inspects login forms and authentication transport hygiene without credential submission.
"""

from typing import Dict, Any, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class AuthenticationReviewModule(ActiveModule):
    name = "AuthenticationReview"
    description = "Active audit of authentication forms, transport hygiene, and password input security"
    stage_name = "Authentication Review"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Authentication Review")
        findings: List[Dict[str, Any]] = []
        target = controller.scope_policy.primary_target

        # Check root page and common login endpoints
        candidates = [target, urljoin(target, "/login"), urljoin(target, "/signin")]
        for page_url in candidates:
            resp = await controller.request("GET", page_url)
            if not resp or resp.status_code != 200:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                password_inputs = form.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
                if not password_inputs:
                    continue

                action = form.get("action", "")
                resolved_action = urljoin(page_url, action)

                # 1. Cleartext HTTP submission for authentication form
                if resolved_action.startswith("http://"):
                    findings.append(self.create_finding(
                        title="Authentication Form Transmits Credentials Over Cleartext HTTP",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        owasp="A02:2021-Cryptographic Failures",
                        cwe="CWE-319",
                        description=f"Login form on {page_url} submits credentials to unencrypted HTTP target: {resolved_action}.",
                        impact="Adversaries on the same network can intercept usernames and passwords in cleartext.",
                        remediation="Ensure all authentication form action attributes point exclusively to HTTPS endpoints.",
                        target_url=target,
                        endpoint=page_url,
                        test_performed="Form action attribute protocol verification",
                        expected="Form action must target https://",
                        observed=f"Form action target: {resolved_action}",
                        raw_evidence=f"Action: {resolved_action}",
                    ))

                # 2. Check for missing CSRF token in authentication / state-changing form
                inputs = form.find_all("input")
                csrf_names = ["csrf", "token", "_token", "authenticity_token", "nonce"]
                has_csrf = any(
                    any(c in inp.get("name", "").lower() for c in csrf_names)
                    for inp in inputs
                )
                if not has_csrf:
                    findings.append(self.create_finding(
                        title="Authentication Form Lacks Anti-CSRF Token",
                        severity="LOW",
                        confidence="CONFIRMED",
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-352",
                        description=f"Login/credential form on {page_url} does not appear to embed an anti-CSRF token input field.",
                        impact="Exposes users to login CSRF attacks where an attacker authenticates the victim into an attacker-controlled account.",
                        remediation="Incorporate anti-CSRF tokens with validation in all state-modifying authentication forms.",
                        target_url=target,
                        endpoint=page_url,
                        test_performed="Form input element scan for anti-CSRF token parameters",
                        expected="Presence of hidden anti-CSRF token input field",
                        observed="No CSRF token field identified in form inputs",
                        raw_evidence=f"Inputs: {[inp.get('name') for inp in inputs]}",
                    ))

        return findings
