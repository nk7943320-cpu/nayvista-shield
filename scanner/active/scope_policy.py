"""
NayVista Shield - Active Scope Policy Enforcement
Enforces strictly bounded same-origin scope manifests, SSRF protection,
and redirect controls during active security assessments.
"""

from urllib.parse import urlparse, urljoin
from typing import List, Set, Optional
from scanner.scope import (
    TargetScope,
    ScopeViolationError,
    TargetSSRFBlockedError,
    TargetInvalidSchemeError,
)

class OutOfScopeError(ScopeViolationError):
    """Raised when an active probe attempts to touch an endpoint outside authorized scope."""
    pass

class ScopePolicy:
    """
    Scope policy manifest defining strict boundaries for active security assessments.
    """
    def __init__(
        self,
        target_url: str,
        allowed_hosts: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        allow_local: bool = False,
    ):
        self.allow_local = allow_local
        self.target_scope = TargetScope(target_url, allow_local=allow_local, raise_on_dns_failure=False)
        self.primary_target = self.target_scope.normalized_target
        self.primary_hostname = self.target_scope.hostname
        self.primary_scheme = self.target_scope.scheme
        self.primary_port = self.target_scope.port
        self.primary_origin = self.target_scope.origin

        # Allowed hosts default to primary hostname (same-origin boundary)
        self.allowed_hosts: Set[str] = {self.primary_hostname}
        if allowed_hosts:
            for host in allowed_hosts:
                clean_host = host.strip().lower()
                if clean_host:
                    self.allowed_hosts.add(clean_host)

        # Excluded paths (e.g. destructive actions, logout, signout)
        self.excluded_paths: List[str] = [
            "/logout",
            "/signout",
            "/log-out",
            "/sign-out",
            "/auth/logout",
            "/api/auth/logout",
            "/delete",
            "/destroy",
        ]
        if excluded_paths:
            for p in excluded_paths:
                p_clean = p.strip()
                if p_clean and p_clean not in self.excluded_paths:
                    self.excluded_paths.append(p_clean)

    def is_in_scope(self, candidate_url: str) -> bool:
        """
        Validates if a URL is strictly within the authorized testing scope:
        1. Valid HTTP/HTTPS scheme.
        2. Hostname is in allowed_hosts.
        3. Port matches primary port (or standard 80->443 upgrade).
        4. Path does not hit excluded endpoints.
        5. SSRF validation passes (no loopback, private, link-local, cloud metadata).
        """
        try:
            parsed = urlparse(candidate_url)
            cand_scheme = (parsed.scheme or "").lower()
            if cand_scheme not in ("http", "https"):
                return False

            cand_host = (parsed.hostname or "").strip("[]").lower()
            if not cand_host or cand_host not in self.allowed_hosts:
                return False

            cand_port = parsed.port or (443 if cand_scheme == "https" else 80)
            is_upgrade = (
                self.primary_scheme == "http"
                and cand_scheme == "https"
                and self.primary_port == 80
                and cand_port == 443
            )
            if cand_port != self.primary_port and not is_upgrade:
                return False

            # Check excluded paths
            path = (parsed.path or "/").lower()
            for excluded in self.excluded_paths:
                if path.startswith(excluded.lower()):
                    return False

            # SSRF validation check on candidate URL
            if not self.allow_local:
                self.target_scope.validate_candidate_url(candidate_url)

            return True
        except Exception:
            return False

    def validate_redirect(self, from_url: str, to_url: str) -> str:
        """
        Resolves relative redirects and enforces that target destination is strictly in scope.
        Raises OutOfScopeError or TargetSSRFBlockedError if redirect target is invalid.
        Returns the resolved absolute URL if valid.
        """
        resolved = urljoin(from_url, to_url)
        if not self.is_in_scope(resolved):
            raise OutOfScopeError(
                f"Redirect from '{from_url}' to '{resolved}' is out of authorized scope or SSRF protected."
            )
        return resolved

    def normalize_url(self, url: str) -> str:
        return self.target_scope.normalize_url(url)
