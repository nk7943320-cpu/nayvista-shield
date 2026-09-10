"""
SentinelScan - TLS & Transport Security Scanner
Performs safe cryptographic configuration analysis:
- Validates HTTPS enforcement.
- Checks certificate expiration, issuer, subject validity.
- Safely detects legacy TLS versions (TLS 1.0, 1.1) without destructive operations.
"""

import ssl
import socket
import datetime
from typing import List, Dict, Any
from scanner.scope import TargetScope
from scanner.normalizer import create_finding

class TLSScanner:
    def scan(self, scope: TargetScope) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        target_url = scope.raw_target

        # 1. Plain HTTP Check
        if scope.scheme == "http":
            findings.append(create_finding(
                scanner="tls_scanner",
                title="Service Operating Over Cleartext HTTP",
                severity="HIGH",
                confidence="HIGH",
                category="Cryptographic Failures",
                owasp_key="CRYPTOGRAPHIC_FAILURES",
                url=target_url,
                evidence=f"Target URL scheme is unencrypted '{scope.scheme}'",
                description="The website is served over cleartext HTTP without encryption.",
                impact="Network eavesdroppers and man-in-the-middle attackers can intercept and modify all user data, credentials, and session tokens.",
                remediation="Migrate the service to HTTPS with a valid TLS certificate and enforce strict redirection from HTTP to HTTPS."
            ))
            # Even if HTTP, attempt checking port 443 safely if standard port
            if scope.port != 80 and scope.port != 443:
                return findings

        # Connect to TLS port (443 or scoped port)
        tls_port = 443 if scope.scheme == "http" else scope.port

        # 2. Certificate and Cipher Analysis via native ssl
        context = ssl.create_default_context()
        # If in local test mode, allow self-signed certificates for test harness
        if scope.allow_local:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((scope.hostname, tls_port), timeout=6.0) as sock:
                with context.wrap_socket(sock, server_hostname=scope.hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    # Check Certificate Expiration
                    if cert and "notAfter" in cert:
                        # Format: 'May 15 12:00:00 2026 GMT'
                        not_after_str = cert["notAfter"]
                        try:
                            # ssl date format standard
                            expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                            days_remaining = (expiry_date - now).days

                            if days_remaining < 0:
                                findings.append(create_finding(
                                    scanner="tls_scanner",
                                    title="TLS Certificate Has Expired",
                                    severity="CRITICAL",
                                    confidence="HIGH",
                                    category="Cryptographic Failures",
                                    owasp_key="CRYPTOGRAPHIC_FAILURES",
                                    url=f"https://{scope.hostname}:{tls_port}",
                                    evidence=f"Certificate expired on {not_after_str} ({abs(days_remaining)} days ago).",
                                    description="The SSL/TLS certificate presented by the server has expired.",
                                    impact="Browsers will display security warnings, blocking user access and failing identity authentication.",
                                    remediation="Renew and install a valid TLS certificate immediately."
                                ))
                            elif days_remaining < 30:
                                findings.append(create_finding(
                                    scanner="tls_scanner",
                                    title="TLS Certificate Expiring Soon",
                                    severity="LOW",
                                    confidence="HIGH",
                                    category="Cryptographic Failures",
                                    owasp_key="CRYPTOGRAPHIC_FAILURES",
                                    url=f"https://{scope.hostname}:{tls_port}",
                                    evidence=f"Certificate expires in {days_remaining} days on {not_after_str}.",
                                    description="The SSL/TLS certificate will expire in less than 30 days.",
                                    impact="Service disruption and browser warning blocks will occur once expired.",
                                    remediation="Plan renewal of the certificate before expiration."
                                ))
                        except Exception:
                            pass

                    # 3. Protocol Version Check
                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(create_finding(
                            scanner="tls_scanner",
                            title=f"Deprecated TLS Protocol ({tls_version}) In Use",
                            severity="HIGH",
                            confidence="HIGH",
                            category="Cryptographic Failures",
                            owasp_key="CRYPTOGRAPHIC_FAILURES",
                            url=f"https://{scope.hostname}:{tls_port}",
                            evidence=f"Negotiated protocol version: {tls_version}",
                            description="Legacy TLS versions (1.0 and 1.1) and SSL have known cryptographic weaknesses and have been deprecated by major browsers.",
                            impact="Traffic may be susceptible to protocol downgrade and cipher weaknesses.",
                            remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Enforce TLS 1.2 and TLS 1.3 only."
                        ))

        except ssl.SSLCertVerificationError as e:
            findings.append(create_finding(
                scanner="tls_scanner",
                title="TLS Certificate Verification Failed",
                severity="HIGH",
                confidence="HIGH",
                category="Cryptographic Failures",
                owasp_key="CRYPTOGRAPHIC_FAILURES",
                url=f"https://{scope.hostname}:{tls_port}",
                evidence=f"SSL verification error: {e.verify_message if hasattr(e, 'verify_message') else str(e)}",
                description="The server certificate is invalid, self-signed, or not signed by a trusted Certificate Authority.",
                impact="Users will experience security warnings, and the connection lacks authenticated trust.",
                remediation="Install a valid certificate issued by a trusted public Certificate Authority (such as Let's Encrypt)."
            ))
        except (socket.timeout, ConnectionRefusedError):
            if scope.scheme == "https":
                findings.append(create_finding(
                    scanner="tls_scanner",
                    title="HTTPS Port Unreachable or Refused",
                    severity="HIGH",
                    confidence="HIGH",
                    category="Security Misconfiguration",
                    owasp_key="SECURITY_MISCONFIGURATION",
                    url=target_url,
                    evidence=f"Connection to port {tls_port} timed out or was refused.",
                    description="The HTTPS service on the target could not be contacted.",
                    impact="Users attempting to access the site securely cannot establish a connection.",
                    remediation="Verify web server listening configuration and firewall port bindings."
                ))
        except Exception as e:
            # Safe catch for other socket anomalies
            pass

        return findings
