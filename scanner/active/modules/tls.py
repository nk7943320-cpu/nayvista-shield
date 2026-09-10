"""
NayVista Shield - Active TLS Validation Module
Validates TLS protocol version, cipher strength, certificate validity, and expiration.
"""

import ssl
import socket
import datetime
import asyncio
from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController

class TLSValidationModule(ActiveModule):
    name = "TLSValidation"
    description = "Active TLS handshake analysis, protocol obsolescence, and certificate audit"
    stage_name = "TLS Validation"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("TLS Validation")
        findings: List[Dict[str, Any]] = []
        scope = controller.scope_policy.target_scope
        target_url = controller.scope_policy.primary_target

        if scope.scheme == "http":
            findings.append(self.create_finding(
                title="Service Operating Over Cleartext HTTP",
                severity="HIGH",
                confidence="CONFIRMED",
                owasp="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                description="The target web application operates over unencrypted cleartext HTTP.",
                impact="All traffic, session tokens, passwords, and user interactions are exposed in plain text to on-path eavesdroppers.",
                remediation="Enforce HTTPS across the entire domain, obtain a TLS certificate, and issue HTTP 301 redirects to HTTPS.",
                target_url=target_url,
                endpoint=target_url,
                test_performed="Protocol scheme verification",
                expected="Target URL must enforce HTTPS scheme",
                observed="Target scheme is http://",
                raw_evidence=f"Scheme: {scope.scheme}, Hostname: {scope.hostname}",
            ))
            if scope.port != 80 and scope.port != 443:
                return findings

        tls_port = 443 if scope.scheme == "http" else scope.port

        loop = asyncio.get_event_loop()
        tls_results = await loop.run_in_executor(
            None, self._inspect_tls, scope.hostname, tls_port, scope.allow_local
        )

        if not tls_results:
            return findings

        # Check for expired or expiring certificate
        days_remaining = tls_results.get("days_remaining")
        if days_remaining is not None:
            if days_remaining < 0:
                findings.append(self.create_finding(
                    title="TLS Certificate Expired",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-298",
                    description=f"The SSL/TLS certificate expired {abs(days_remaining)} days ago ({tls_results.get('not_after')}).",
                    impact="Clients attempting connection will face severe security warnings and MITM protection blocks.",
                    remediation="Renew and deploy an active valid TLS certificate immediately.",
                    target_url=target_url,
                    endpoint=f"https://{scope.hostname}:{tls_port}",
                    test_performed="TLS handshake peer certificate extraction",
                    expected="Certificate should be actively valid with future expiration date",
                    observed=f"Expired on: {tls_results.get('not_after')} ({abs(days_remaining)} days overdue)",
                    raw_evidence=str(tls_results),
                ))
            elif days_remaining < 30:
                findings.append(self.create_finding(
                    title="TLS Certificate Expiring Soon (< 30 Days)",
                    severity="LOW",
                    confidence="CONFIRMED",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-298",
                    description=f"The SSL/TLS certificate expires in {days_remaining} days ({tls_results.get('not_after')}).",
                    impact="If not renewed promptly, service disruption and cryptographic warning banners will occur upon expiration.",
                    remediation="Schedule automated certificate renewal before expiration.",
                    target_url=target_url,
                    endpoint=f"https://{scope.hostname}:{tls_port}",
                    test_performed="TLS certificate validity timeframe calculation",
                    expected="Certificate validity window > 30 days remaining",
                    observed=f"{days_remaining} days remaining before expiration",
                    raw_evidence=str(tls_results),
                ))

        # Check protocol version
        tls_ver = tls_results.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(self.create_finding(
                title=f"Deprecated TLS Protocol In Use ({tls_ver})",
                severity="HIGH",
                confidence="CONFIRMED",
                owasp="A02:2021-Cryptographic Failures",
                cwe="CWE-326",
                description=f"The server negotiated connection using legacy protocol {tls_ver}. TLS 1.0 and 1.1 are deprecated by NIST and RFC 8996.",
                impact="Deprecated protocols suffer from known cryptographic weaknesses (POODLE, BEAST) and lack modern cipher suites.",
                remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Enforce TLS 1.2 and TLS 1.3.",
                target_url=target_url,
                endpoint=f"https://{scope.hostname}:{tls_port}",
                test_performed="TLS protocol handshake version negotiation",
                expected="Negotiation of TLS 1.2 or TLS 1.3 only",
                observed=f"Negotiated version: {tls_ver}",
                raw_evidence=f"TLS Version: {tls_ver}",
            ))

        # Check cipher strength
        cipher_info = tls_results.get("cipher")
        if cipher_info and isinstance(cipher_info, tuple) and len(cipher_info) > 0:
            cipher_name = cipher_info[0]
            weak_indicators = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]
            if any(w in cipher_name.upper() for w in weak_indicators):
                findings.append(self.create_finding(
                    title=f"Weak TLS Cipher Suite Negotiated ({cipher_name})",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-326",
                    description=f"Server negotiated connection using weak or obsolete cipher: {cipher_name}.",
                    impact="Weak ciphers are susceptible to cryptanalytic attacks and decryption of recorded network traffic.",
                    remediation="Reconfigure server cipher suites to prioritize AEAD ciphers (e.g. AES-GCM, ChaCha20-Poly1305).",
                    target_url=target_url,
                    endpoint=f"https://{scope.hostname}:{tls_port}",
                    test_performed="TLS cipher suite negotiation",
                    expected="Strong AEAD ciphers only (e.g. ECDHE-RSA-AES128-GCM-SHA256)",
                    observed=f"Cipher: {cipher_name}",
                    raw_evidence=f"Cipher tuple: {cipher_info}",
                ))

        return findings

    def _inspect_tls(self, hostname: str, port: int, allow_local: bool) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        context = ssl.create_default_context()
        if allow_local:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["tls_version"] = ssock.version()
                    result["cipher"] = ssock.cipher()
                    cert = ssock.getpeercert()
                    if cert and "notAfter" in cert:
                        not_after_str = cert["notAfter"]
                        result["not_after"] = not_after_str
                        try:
                            expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                            result["days_remaining"] = (expiry_date - now).days
                        except Exception:
                            pass
        except Exception:
            pass
        return result
