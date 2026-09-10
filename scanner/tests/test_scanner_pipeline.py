"""
SentinelScan - Unit & Integration Test Suite
Verifies scope enforcement, SSRF protection, normalizer sanitization,
scoring algorithm, and end-to-end scanner execution against the local mock server.
"""

import unittest
import asyncio
from scanner.scope import TargetScope, ScopeViolationError
from scanner.normalizer import create_finding, deduplicate_findings, sanitize_evidence
from scanner.scoring import calculate_security_score
from scanner.orchestrator import ScanOrchestrator
from scanner.tests.mock_target_server import MockTestServer

class TestSentinelScanPipeline(unittest.TestCase):

    def test_scope_validation_and_ssrf(self):
        # Disallow invalid schemes
        with self.assertRaises(ScopeViolationError):
            TargetScope("ftp://example.com")

        with self.assertRaises(ScopeViolationError):
            TargetScope("javascript:alert(1)")

        # Disallow loopback / SSRF by default
        with self.assertRaises(ScopeViolationError):
            TargetScope("http://127.0.0.1", allow_local=False)

        with self.assertRaises(ScopeViolationError):
            TargetScope("http://localhost", allow_local=False)

        with self.assertRaises(ScopeViolationError):
            TargetScope("http://169.254.169.254/latest/meta-data/", allow_local=False)

        # Allow valid public targets
        scope = TargetScope("https://example.com/login?ref=1", allow_local=True)
        self.assertEqual(scope.hostname, "example.com")
        self.assertEqual(scope.port, 443)
        self.assertEqual(scope.scheme, "https")

        # Same origin checks
        self.assertTrue(scope.is_same_origin("https://example.com/account"))
        self.assertTrue(scope.is_same_origin("https://example.com:443/settings"))
        # Different hostname
        self.assertFalse(scope.is_same_origin("https://sub.example.com/"))
        self.assertFalse(scope.is_same_origin("https://evil.com/"))
        # Different port
        self.assertFalse(scope.is_same_origin("https://example.com:8443/"))

    def test_secret_sanitization_in_evidence(self):
        raw_evidence = "Found cookie Set-Cookie: session_token=secret_value_12345; Path=/; Secure"
        cleaned = sanitize_evidence(raw_evidence)
        self.assertNotIn("secret_value_12345", cleaned)
        self.assertIn("REDACTED", cleaned)

        auth_evidence = "Authorization: Bearer my_secret_jwt_token_abcdef"
        cleaned_auth = sanitize_evidence(auth_evidence)
        self.assertNotIn("my_secret_jwt_token_abcdef", cleaned_auth)

    def test_deduplication(self):
        f1 = create_finding(
            scanner="headers_scanner",
            title="CSP Missing",
            severity="MEDIUM",
            confidence="HIGH",
            category="Security Misconfiguration",
            owasp_key="SECURITY_MISCONFIGURATION",
            url="https://example.com/page1",
            evidence="CSP missing",
            description="desc",
            impact="impact",
            remediation="remedy"
        )
        f2 = create_finding(
            scanner="headers_scanner",
            title="CSP Missing",
            severity="MEDIUM",
            confidence="HIGH",
            category="Security Misconfiguration",
            owasp_key="SECURITY_MISCONFIGURATION",
            url="https://example.com/page2",
            evidence="CSP missing",
            description="desc",
            impact="impact",
            remediation="remedy"
        )

        deduped = deduplicate_findings([f1, f2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(len(deduped[0]["affected_urls"]), 2)

    def test_security_score_calculation(self):
        findings = [
            {"severity": "CRITICAL", "confidence": "HIGH"},
            {"severity": "HIGH", "confidence": "HIGH"},
            {"severity": "LOW", "confidence": "HIGH"},
        ]
        result = calculate_security_score(findings)
        self.assertLess(result["score"], 70)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["counts"]["CRITICAL"], 1)

    def test_end_to_end_mock_assessment(self):
        # Start local mock server
        server = MockTestServer(host="127.0.0.1", port=8999)
        server.start()

        try:
            target_url = "http://127.0.0.1:8999"
            orchestrator = ScanOrchestrator(target_url=target_url, allow_local=True)
            result = asyncio.run(orchestrator.run_scan())

            self.assertEqual(result["target"], target_url)
            self.assertGreaterEqual(result["pages_scanned"], 2)

            titles = [f["title"] for f in result["findings"]]
            # Check for header findings
            self.assertTrue(any("Content Security Policy" in t for t in titles))
            self.assertTrue(any("X-Content-Type-Options" in t for t in titles))

            # Check cookie security finding
            self.assertTrue(any("Cookie 'session_token' Missing" in t for t in titles))
            # Verify secret session token was never leaked
            for f in result["findings"]:
                self.assertNotIn("mock_secret_session_token_12345", f["evidence"])

            # Check TRACE method finding
            self.assertTrue(any("TRACE" in t for t in titles))

            # Check Tech detector captured WordPress or Apache or PHP
            tech_names = str(result["technologies"])
            self.assertTrue("PHP" in tech_names or "WordPress" in tech_names or "Apache" in tech_names)

            # Check attack surface inventory discovered /login and forms
            inv = result["inventory"]
            self.assertIn("/login", inv["endpoints"])
            self.assertIn("password", inv["parameters"])

            # Verify external URL was NOT crawled
            crawled_urls = [p["url"] for p in result["pages"]]
            for url in crawled_urls:
                self.assertTrue(url.startswith("http://127.0.0.1:8999"))
                self.assertNotIn("unrelated-third-party.com", url)

        finally:
            server.stop()

if __name__ == "__main__":
    unittest.main()
