"""
NayVista Shield - Network Port Exposure Scanner
Performs safe, non-destructive TCP connect checks across a curated set of common services.
Enforces contextual risk classification (OPEN != automatically vulnerable).
Generates structured security findings for exposed sensitive or database services.
"""

import socket
import asyncio
from typing import Dict, List, Any, Tuple
from scanner.scope import TargetScope

# Curated set of standard service ports per NayVista Shield specification
CURATED_PORT_REGISTRY = [
    (21,    "FTP",           "HIGH",     "Legacy cleartext file transfer service exposed."),
    (22,    "SSH",           "REVIEW",   "Remote administrative shell exposed."),
    (23,    "Telnet",        "HIGH",     "Insecure unencrypted remote shell exposed."),
    (25,    "SMTP",          "REVIEW",   "Mail transfer service exposed."),
    (80,    "HTTP",          "EXPECTED", "Standard unencrypted HTTP web service exposed."),
    (110,   "POP3",          "REVIEW",   "Post Office Protocol mail service exposed."),
    (143,   "IMAP",          "REVIEW",   "Internet Message Access Protocol service exposed."),
    (443,   "HTTPS",         "EXPECTED", "Standard encrypted HTTPS web service exposed."),
    (445,   "SMB",           "HIGH",     "Server Message Block network sharing service exposed."),
    (1433,  "MSSQL",         "HIGH",     "Microsoft SQL Server database exposed."),
    (1521,  "Oracle",        "HIGH",     "Oracle Database listener exposed."),
    (3306,  "MySQL",         "HIGH",     "MySQL Database service exposed."),
    (3389,  "RDP",           "HIGH",     "Remote Desktop Protocol service exposed."),
    (5432,  "PostgreSQL",    "HIGH",     "PostgreSQL Database service exposed."),
    (6379,  "Redis",         "HIGH",     "Redis in-memory data store exposed."),
    (8080,  "HTTP-Proxy",    "REVIEW",   "Alternative HTTP / application proxy service exposed."),
    (8443,  "HTTPS-Alt",     "REVIEW",   "Alternative encrypted HTTPS service exposed."),
    (9200,  "Elasticsearch", "HIGH",     "Elasticsearch search and analytics cluster exposed."),
    (27017, "MongoDB",       "HIGH",     "MongoDB NoSQL database service exposed."),
]

class NetworkExposureScanner:
    def __init__(self, timeout: float = 0.5, max_concurrency: int = 8, stage_timeout: float = 6.0):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.stage_timeout = stage_timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.status = "PENDING"
        self.limitation: Dict[str, Any] = {}

    async def scan_async(self, scope: TargetScope) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Scans curated ports asynchronously and returns:
          (exposure_entries, security_findings)
        """
        # Prerequisite: DNS must have succeeded and have a permitted resolved IP
        if scope.dns_status != "SUCCESS" or (not scope.resolved_ipv4 and not scope.all_ips):
            self.status = "SKIPPED"
            self.limitation = {
                "stage": "PORT EXPOSURE",
                "status": "SKIPPED",
                "code": "NO_RESOLVED_TARGET_IP",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Port exposure assessment requires a successfully resolved and permitted target IP.",
            }
            return [], []

        host = scope.resolved_ipv4 or (scope.all_ips[0] if scope.all_ips else scope.hostname)
        # If target has a custom port in URL, ensure it is included in probe list
        ports_to_check = list(CURATED_PORT_REGISTRY)
        target_port = scope.port
        if target_port and not any(p[0] == target_port for p in ports_to_check):
            service_guess = "HTTPS-Custom" if scope.scheme == "https" else "HTTP-Custom"
            ports_to_check.append((target_port, service_guess, "EXPECTED", "Target application service port."))

        tasks = [self._probe_port(host, port, service, default_risk) for port, service, default_risk, _ in ports_to_check]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=self.stage_timeout)
            self.status = "COMPLETED"
        except asyncio.TimeoutError:
            self.status = "LIMITED"
            self.limitation = {
                "stage": "PORT EXPOSURE",
                "status": "LIMITED",
                "code": "PORT_PROBE_TIMEOUT",
                "category": "ASSESSMENT_LIMITATION",
                "reason": "Port exposure probe exceeded maximum allocated stage timeout.",
            }
            results = []

        exposure_entries: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        for port, service, state, exposure, risk in results:
            entry = {
                "port": port,
                "service": service,
                "state": state,
                "exposure": exposure,
                "risk": risk,
            }
            exposure_entries.append(entry)

            # Generate security findings for open risky services
            if state == "OPEN":
                if risk == "HIGH":
                    finding_id = f"NS-PORT-{port:03d}"
                    findings.append({
                        "id": finding_id,
                        "scanner": "NetworkExposureScanner",
                        "title": f"Public {service} Service Exposure (TCP/{port})",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "category": "EXPOSURE",
                        "owasp": "A05:2021-Security Misconfiguration",
                        "cwe": "CWE-668",
                        "url": f"{scope.scheme}://{scope.hostname}:{port}",
                        "affected_component": f"TCP/{port} ({service})",
                        "description": (
                            f"The {service} service on port TCP/{port} was found to be externally open and "
                            f"reachable from the public internet. Database, cache, and management services should "
                            f"never be directly accessible to untrusted networks."
                        ),
                        "evidence": f"TCP/{port} is externally reachable on {scope.hostname} ({host}).",
                        "impact": (
                            f"Direct exposure of {service} to the public internet enables unauthorized connection "
                            f"attempts, brute-force attacks, data exfiltration, or remote exploit vectors."
                        ),
                        "remediation": (
                            f"Restrict TCP/{port} ({service}) access using network security groups, firewalls, or VPC "
                            f"access control lists. Bind the service to loopback (127.0.0.1) or private internal subnets."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/668.html",
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                        ],
                    })
                elif risk == "REVIEW" and service == "SSH":
                    findings.append({
                        "id": "NS-PORT-022",
                        "scanner": "NetworkExposureScanner",
                        "title": "Public SSH Administration Service Reachable (TCP/22)",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "category": "EXPOSURE",
                        "owasp": "A05:2021-Security Misconfiguration",
                        "cwe": "CWE-200",
                        "url": f"{scope.scheme}://{scope.hostname}:22",
                        "affected_component": "TCP/22 (SSH)",
                        "description": (
                            "SSH remote administration service is reachable externally on TCP/22. "
                            "While common for administrative access, public reachability warrants verification "
                            "of hardening controls (key-only authentication, disabled root login, rate limiting)."
                        ),
                        "evidence": f"TCP/22 is externally reachable on {scope.hostname} ({host}).",
                        "impact": "Exposes administrative login interface to internet-wide automated scanning and dictionary attacks.",
                        "remediation": (
                            "Enforce public-key authentication, disable password authentication, disable root login, "
                            "and restrict access via a dedicated VPN or IP allowlisting."
                        ),
                        "references": [
                            "https://cwe.mitre.org/data/definitions/200.html",
                        ],
                    })

        # Sort exposure entries by port number
        exposure_entries.sort(key=lambda x: x["port"])
        return exposure_entries, findings

    async def _probe_port(self, host: str, port: int, service: str, default_risk: str) -> Tuple[int, str, str, str, str]:
        """Probes a single TCP port and classifies state, exposure, and contextual risk with bounded concurrency."""
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return (port, service, "OPEN", "External", default_risk)
            except (ConnectionRefusedError, ConnectionResetError):
                return (port, service, "CLOSED", "-", "-")
            except (asyncio.TimeoutError, socket.timeout):
                return (port, service, "FILTERED", "-", "-")
            except OSError:
                return (port, service, "FILTERED", "-", "-")

    def scan(self, scope: TargetScope) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synchronous wrapper for port scanning."""
        return asyncio.run(self.scan_async(scope))
