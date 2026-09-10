"""
NayVista Shield - Target Scope & SSRF Enforcement Module
Provides strict boundary enforcement:
- Validates URLs and protocols (HTTP/HTTPS only).
- Protects against SSRF (RFC1918, loopbacks, cloud metadata like 169.254.169.254).
- Enforces strict same-origin constraints on all crawled links.
- Gracefully classifies DNS and address resolution failures.
"""

import os
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse, urljoin, urlunparse

class ScopeViolationError(ValueError):
    """Base error for scope or boundary violations."""
    pass

class TargetUnavailableError(ScopeViolationError):
    """Raised when the domain cannot be resolved via DNS."""
    pass

class TargetSSRFBlockedError(ScopeViolationError):
    """Raised when an internal or cloud-metadata IP is targeted."""
    pass

class TargetInvalidSchemeError(ScopeViolationError):
    """Raised when a non-HTTP/HTTPS protocol is submitted."""
    pass

class TargetScope:
    def __init__(self, target_url: str, allow_local: bool = False, raise_on_dns_failure: bool = False):
        self.allow_local = allow_local or os.environ.get("ALLOW_LOCAL_TARGETS", "").lower() in ("1", "true", "yes")
        self.raise_on_dns_failure = raise_on_dns_failure
        self.raw_target = target_url.strip()
        self.parsed = urlparse(self.raw_target)

        if not self.parsed.scheme or self.parsed.scheme.lower() not in ("http", "https"):
            raise TargetInvalidSchemeError(f"Invalid URL scheme '{self.parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        if not self.parsed.hostname:
            raise ScopeViolationError("Target URL must specify a valid hostname.")

        self.scheme = self.parsed.scheme.lower()
        self.hostname = self.parsed.hostname.lower()
        self.port = self.parsed.port or (443 if self.scheme == "https" else 80)
        
        # Base origin format: https://example.com:443
        self.origin = f"{self.scheme}://{self.hostname}:{self.port}"
        self.normalized_target = self.normalize_url(self.raw_target)

        # DNS resolution and SSRF boundaries
        self.resolved_ipv4: Optional[str] = None
        self.resolved_ipv6: Optional[str] = None
        self.all_ips: list = []
        self.dns_status: str = "PENDING"
        self.dns_error: Optional[str] = None
        self._validate_ssrf(self.hostname)

    def _validate_ssrf(self, hostname: str):
        """Validates that hostname does not resolve to loopback, private or link-local/cloud metadata, capturing DNS details."""
        clean_host = hostname.strip("[]").lower()

        # Check for literal IP (IPv4 or IPv6)
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            # Check for IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1)
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped

            ip_str = str(ip_obj)
            self.all_ips.append(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                self.resolved_ipv4 = ip_str
            else:
                self.resolved_ipv6 = ip_str

            self.dns_status = "SUCCESS"
            self.resolved_ipv6 = self.resolved_ipv6 or "Not detected"

            if not self.allow_local:
                self._check_ip_safety(ip_obj)
            return
        except ValueError:
            pass

        # Check for banned hostname aliases before DNS
        banned_hosts = {
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "metadata.google.internal", "instance-data", "metadata",
        }
        if not self.allow_local and (clean_host in banned_hosts or clean_host.endswith(".localhost") or clean_host.endswith(".internal")):
            raise TargetSSRFBlockedError(f"SSRF Protection: Access to '{hostname}' is strictly blocked.")

        # Resolve hostname to extract resolved IPv4 / IPv6 addresses
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            for item in addr_info:
                ip_str = item[4][0]
                if ip_str not in self.all_ips:
                    self.all_ips.append(ip_str)
                ip_obj = ipaddress.ip_address(ip_str)
                if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                    ip_obj = ip_obj.ipv4_mapped

                if isinstance(ip_obj, ipaddress.IPv4Address) and not self.resolved_ipv4:
                    self.resolved_ipv4 = str(ip_obj)
                elif isinstance(ip_obj, ipaddress.IPv6Address) and not self.resolved_ipv6:
                    self.resolved_ipv6 = str(ip_obj)

                if not self.allow_local:
                    self._check_ip_safety(ip_obj)

            self.dns_status = "SUCCESS"
            self.resolved_ipv6 = self.resolved_ipv6 or "Not detected"
        except socket.gaierror as e:
            self.dns_status = "FAILED"
            self.dns_error = f"Hostname could not be resolved: {e}"
            self.resolved_ipv4 = None
            self.resolved_ipv6 = None
            self.all_ips = []
            if self.raise_on_dns_failure:
                raise TargetUnavailableError(f"DNS Resolution Failed: Unable to resolve hostname '{hostname}': {e}")

    def _check_ip_safety(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
        """Reject private, loopback, link-local, multicast, or reserved IPs."""
        if self.allow_local:
            return

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise TargetSSRFBlockedError(
                f"SSRF Protection: Target IP address '{ip}' is in a private, loopback, or reserved range."
            )
        
        # Specific check for AWS / GCP / Azure metadata address (169.254.169.254)
        if str(ip) == "169.254.169.254":
            raise TargetSSRFBlockedError("SSRF Protection: Cloud metadata IP (169.254.169.254) is strictly prohibited.")

    def validate_candidate_url(self, candidate_url: str) -> None:
        """
        Validates any discovered or redirect candidate URL before connecting:
        - Scheme must be strictly HTTP or HTTPS (blocks file://, gopher://, javascript:, data:).
        - Destination IP / hostname must pass SSRF safety check.
        """
        parsed = urlparse(candidate_url)
        cand_scheme = (parsed.scheme or "").lower()
        if cand_scheme not in ("http", "https"):
            raise TargetInvalidSchemeError(
                f"Unsafe URL scheme '{cand_scheme}'. Only HTTP and HTTPS are permitted."
            )

        cand_host = (parsed.hostname or "").lower()
        if not cand_host:
            raise ScopeViolationError("Candidate URL lacks a valid hostname.")

        if not self.allow_local:
            self._validate_ssrf(cand_host)

    def is_same_origin(self, candidate_url: str) -> bool:
        """
        Enforces strict same-origin constraints:
        - Same hostname (exact match)
        - Same port (or standard 80->443 HTTP to HTTPS upgrade)
        - Same scheme (or http -> https upgrade)
        - Destination re-validated against SSRF boundary
        """
        try:
            parsed = urlparse(candidate_url)
            if not parsed.hostname:
                return False

            cand_scheme = parsed.scheme.lower()
            cand_host = parsed.hostname.strip("[]").lower()
            cand_port = parsed.port or (443 if cand_scheme == "https" else 80)
            target_host = self.hostname.strip("[]").lower()

            # Strict hostname match
            if cand_host != target_host:
                return False

            # Allow scheme if matching or upgrade from http to https on standard ports
            is_http_upgrade = (self.scheme == "http" and cand_scheme == "https" and self.port == 80 and cand_port == 443)
            
            # Port check (allowing standard http->https upgrade port transition)
            if cand_port != self.port and not is_http_upgrade:
                return False

            if cand_scheme != self.scheme and not (self.scheme == "http" and cand_scheme == "https"):
                return False

            # Validate SSRF on candidate URL to block redirect or alias attacks
            self.validate_candidate_url(candidate_url)

            return True
        except Exception:
            return False

    def normalize_url(self, url: str, base_url: str | None = None) -> str:
        """
        Resolves relative URLs to absolute, removes fragments, normalizes path.
        """
        if base_url:
            resolved = urljoin(base_url, url)
        else:
            resolved = urljoin(self.raw_target, url)

        parsed = urlparse(resolved)
        # Strip fragment
        cleaned = parsed._replace(fragment="")
        # Remove trailing slash if path is not root
        path = cleaned.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        cleaned = cleaned._replace(path=path)
        return urlunparse(cleaned)

def validate_candidate_url(candidate_url: str, allow_local: bool = False) -> bool:
    """
    Stand-alone helper to validate a URL against scheme and SSRF constraints.
    Returns True if valid, False otherwise.
    """
    try:
        TargetScope(candidate_url, allow_local=allow_local)
        return True
    except Exception:
        return False

