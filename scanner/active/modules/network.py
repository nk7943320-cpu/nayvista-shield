"""
NayVista Shield - Network / Service Validation Module
Audits curated network service exposure on the resolved target IP.
"""

import asyncio
import socket
from typing import Dict, Any, List
from scanner.active.base import ActiveModule
from scanner.active.controller import ActiveRequestController
from scanner.modules.network_exposure import CURATED_PORT_REGISTRY

class NetworkServiceValidationModule(ActiveModule):
    name = "NetworkServiceValidation"
    description = "Active network service exposure audit and database/admin exposure analysis"
    stage_name = "Network Validation"

    async def execute(self, controller: ActiveRequestController, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        controller.set_current_stage("Network Validation")
        findings: List[Dict[str, Any]] = []
        scope = controller.scope_policy.target_scope

        resolved_ip = scope.resolved_ipv4 or (scope.all_ips[0] if scope.all_ips else None)
        if not resolved_ip:
            return findings

        # Run curated port probes
        exposure_list: List[Dict[str, Any]] = []
        for port, service, risk_tier, desc in CURATED_PORT_REGISTRY:
            is_open = await self._check_port(resolved_ip, port)
            if is_open:
                exposure_list.append({
                    "port": port,
                    "service": service,
                    "state": "OPEN",
                    "exposure": "Exposed",
                    "risk": risk_tier,
                })

                # High-risk database / cache exposures
                if port in (6379, 3306, 5432, 27017):
                    findings.append(self.create_finding(
                        title=f"Direct Internet Exposure of Database Service ({service.upper()} Port {port})",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-284",
                        description=f"Port {port} ({service}) was detected OPEN on the public target IP ({resolved_ip}). Database management engines should never be directly accessible from the public internet.",
                        impact="Attackers can attempt credential brute force, exploit unauthenticated daemon protocols, or target known service vulnerabilities to compromise data integrity.",
                        remediation="Bind database services to localhost or private network interfaces only. Implement strict firewall rules and VPN access gates.",
                        target_url=scope.normalized_target,
                        endpoint=f"{resolved_ip}:{port}",
                        test_performed=f"TCP handshake probe on port {port} ({service})",
                        expected="Port should be filtered or closed to public traffic",
                        observed=f"Port {port} responded with OPEN state",
                        raw_evidence=f"IP: {resolved_ip}, Port: {port}, State: OPEN, Service: {service}",
                    ))
                elif port == 3389:
                    findings.append(self.create_finding(
                        title="Remote Desktop Protocol (RDP) Exposed to Public Internet",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-284",
                        description=f"Port 3389 (RDP) is publicly accessible on {resolved_ip}. Exposing remote desktop management interfaces invites automated credential stuffing and ransomware attacks.",
                        impact="High risk of unauthorized administrative access and lateral movement via compromised credentials or RDP exploits.",
                        remediation="Place RDP behind a zero-trust network access gateway, VPN, or firewall allowlist with multi-factor authentication enforced.",
                        target_url=scope.normalized_target,
                        endpoint=f"{resolved_ip}:{port}",
                        test_performed="TCP handshake probe on port 3389 (RDP)",
                        expected="Port 3389 should be closed or restricted to authorized IP ranges",
                        observed=f"Port 3389 responded OPEN on {resolved_ip}",
                        raw_evidence=f"IP: {resolved_ip}, Port: 3389, State: OPEN",
                    ))
                elif port == 21:
                    findings.append(self.create_finding(
                        title="Unencrypted FTP Service Exposed (Port 21)",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        owasp="A02:2021-Cryptographic Failures",
                        cwe="CWE-319",
                        description=f"Port 21 (FTP) is open on {resolved_ip}. Legacy FTP transmits credentials and files in cleartext over the network.",
                        impact="Cleartext authentication credentials and transferred files are subject to eavesdropping and interception.",
                        remediation="Migrate to secure SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS) and disable plain FTP.",
                        target_url=scope.normalized_target,
                        endpoint=f"{resolved_ip}:{port}",
                        test_performed="TCP handshake probe on port 21 (FTP)",
                        expected="FTP should be disabled in favor of encrypted transport",
                        observed="Port 21 responded OPEN",
                        raw_evidence=f"IP: {resolved_ip}, Port: 21, State: OPEN",
                    ))

        context["network_exposure"] = exposure_list
        return findings

    async def _check_port(self, host: str, port: int, timeout: float = 1.2) -> bool:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_tcp_connect, host, port, timeout),
                timeout=timeout + 0.3
            )
        except Exception:
            return False

    def _sync_tcp_connect(self, host: str, port: int, timeout: float) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
