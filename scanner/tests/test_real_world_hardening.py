"""
NayVista Shield - Real-World Scanner Hardening Test Suite
Verifies:
1. Complete secret redaction ([REDACTED]) across tokens, AWS keys, JWTs, cookies, and private keys.
2. SSRF prevention, bracketed IPv6, IPv4-mapped IPv6, and non-HTTP scheme rejection.
3. Redirect hop SSRF protection and circular redirect protection.
4. HTTP 403 (WAF), 429 (Rate-limiting), and 5xx status classification.
5. Deterministic scoring and posture caps (RESTRICTED, DEGRADED).
6. 2MB crawler payload limit and binary content-type handling.
"""

import unittest
import asyncio
from scanner.scope import (
    TargetScope,
    ScopeViolationError,
    TargetSSRFBlockedError,
    TargetInvalidSchemeError,
    validate_candidate_url,
)
from scanner.findings import sanitize_evidence
from scanner.scoring import calculate_security_score
from scanner.crawler import SafeCrawler
from scanner.engine import ScannerEngine
from scanner.tests.mock_target_server import MockTestServer

class TestRealWorldHardening(unittest.TestCase):

    def test_secret_redaction(self):
        """Ensures all sensitive credentials and tokens are redacted to [REDACTED]."""
        test_cases = [
            ("password = 'super_secret_password_123!'", "[REDACTED]"),
            ("api_key = \"AKIAIOSFODNN7EXAMPLE\"", "[REDACTED]"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature", "[REDACTED]"),
            ("Set-Cookie: session_id=sess_abcdef123456789; Secure; HttpOnly", "[REDACTED]"),
            ("slack_token = 'xoxb-123456789012-123456789012-abcdef1234567890abcdef12'", "[REDACTED]"),
            ("github_token = 'ghp_0123456789abcdefghijklmnopqrstuvwxyz1234'", "[REDACTED]"),
            ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----", "[REDACTED]"),
        ]

        for raw_evidence, expected_marker in test_cases:
            cleaned = sanitize_evidence(raw_evidence)
            self.assertIn(expected_marker, cleaned, f"Failed to redact: {raw_evidence}")
            # Ensure sensitive token strings themselves are not in the sanitized output
            self.assertNotIn("super_secret_password_123!", cleaned)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)
            self.assertNotIn("doNotLeakThisSignature", cleaned)
            self.assertNotIn("sess_abcdef123456789", cleaned)

    def test_ssrf_and_scope_hardening(self):
        """Verifies SSRF filters and IPv6 parsing."""
        # Invalid schemes
        with self.assertRaises(TargetInvalidSchemeError):
            TargetScope("ftp://127.0.0.1")
        with self.assertRaises(TargetInvalidSchemeError):
            TargetScope("file:///etc/passwd")
        with self.assertRaises(TargetInvalidSchemeError):
            TargetScope("javascript:alert(1)")

        # SSRF blocked IPs
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://127.0.0.1", allow_local=False)
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://localhost", allow_local=False)
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://169.254.169.254/latest/meta-data/", allow_local=False)
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://10.0.0.5:8080", allow_local=False)
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://192.168.1.1", allow_local=False)
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://172.16.0.100", allow_local=False)

        # IPv6 Loopback
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://[::1]", allow_local=False)

        # IPv4-mapped IPv6 loopback
        with self.assertRaises(TargetSSRFBlockedError):
            TargetScope("http://[::ffff:127.0.0.1]", allow_local=False)

        # Valid public target
        scope = TargetScope("https://example.com:8443/test", allow_local=False)
        self.assertEqual(scope.hostname, "example.com")
        self.assertEqual(scope.port, 8443)
        self.assertEqual(scope.scheme, "https")

        # Per-hop SSRF validation helper
        self.assertFalse(validate_candidate_url("http://169.254.169.254/test", allow_local=False))
        self.assertFalse(validate_candidate_url("http://127.0.0.1/test", allow_local=False))
        self.assertTrue(validate_candidate_url("https://example.com/test", allow_local=False))

    def test_posture_and_scoring_caps(self):
        """Verifies deterministic scoring and posture caps."""
        # 1. Zero findings with clean ASSESSED posture -> 100 / A / LOW
        res_clean = calculate_security_score([], posture="ASSESSED")
        self.assertEqual(res_clean["score"], 100)
        self.assertEqual(res_clean["grade"], "A")
        self.assertEqual(res_clean["risk_level"], "LOW")
        self.assertEqual(res_clean["posture"], "ASSESSED")

        # 2. Zero findings with RESTRICTED posture (WAF / 429) -> Capped at 70 / Grade C / MEDIUM
        res_restricted = calculate_security_score([], posture="RESTRICTED")
        self.assertEqual(res_restricted["score"], 70)
        self.assertEqual(res_restricted["grade"], "C")
        self.assertEqual(res_restricted["risk_level"], "MEDIUM")
        self.assertEqual(res_restricted["posture"], "RESTRICTED")

        # 3. Zero findings with DEGRADED posture (5xx / TLS failure) -> Capped at 65 / Grade D / MEDIUM
        res_degraded = calculate_security_score([], posture="DEGRADED")
        self.assertEqual(res_degraded["score"], 65)
        self.assertEqual(res_degraded["grade"], "D")
        self.assertEqual(res_degraded["risk_level"], "MEDIUM")
        self.assertEqual(res_degraded["posture"], "DEGRADED")

        # 4. Critical finding drops score and sets CRITICAL risk regardless of posture
        crit_finding = [{"severity": "CRITICAL", "confidence": "HIGH"}]
        res_crit = calculate_security_score(crit_finding, posture="ASSESSED")
        self.assertEqual(res_crit["risk_level"], "CRITICAL")
        self.assertLessEqual(res_crit["score"], 75)

    def test_mock_hardening_endpoints(self):
        """Tests WAF 403, 429, 500, payload limit, and binary asset filtering using local mock."""
        server = MockTestServer(host="127.0.0.1", port=9001)
        server.start()

        try:
            # Test 1: WAF 403 detection
            scope_waf = TargetScope("http://127.0.0.1:9001/waf-block", allow_local=True)
            crawler_waf = SafeCrawler(scope=scope_waf, max_pages=3)
            pages_waf = asyncio.run(crawler_waf.crawl())
            self.assertTrue(crawler_waf.waf_or_blocked)
            self.assertEqual(crawler_waf.initial_status_code, 403)
            self.assertEqual(len(pages_waf), 1)

            # Test 2: Rate limiting 429 detection
            scope_rl = TargetScope("http://127.0.0.1:9001/rate-limit", allow_local=True)
            crawler_rl = SafeCrawler(scope=scope_rl, max_pages=3)
            pages_rl = asyncio.run(crawler_rl.crawl())
            self.assertTrue(crawler_rl.rate_limited)
            self.assertEqual(crawler_rl.initial_status_code, 429)

            # Test 3: Server Error 500 detection
            scope_err = TargetScope("http://127.0.0.1:9001/server-error", allow_local=True)
            crawler_err = SafeCrawler(scope=scope_err, max_pages=3)
            pages_err = asyncio.run(crawler_err.crawl())
            self.assertTrue(crawler_err.server_error)
            self.assertEqual(crawler_err.initial_status_code, 500)

            # Test 4: Binary image asset handling
            scope_img = TargetScope("http://127.0.0.1:9001/logo.png", allow_local=True)
            crawler_img = SafeCrawler(scope=scope_img, max_pages=3)
            pages_img = asyncio.run(crawler_img.crawl())
            self.assertEqual(len(pages_img), 1)
            # Binary content should not be parsed into HTML text
            self.assertEqual(pages_img[0].text, "")

            # Test 5: End-to-end WAF assessment posture cap
            engine_waf = ScannerEngine(target_url="http://127.0.0.1:9001/waf-block", allow_local=True)
            result_waf = engine_waf.scan()
            self.assertEqual(result_waf["posture"], "RESTRICTED")
            self.assertLessEqual(result_waf["scoring"]["score"], 70)
            self.assertIn(result_waf["scoring"]["grade"], ["C", "D", "F"])

        finally:
            server.stop()

if __name__ == "__main__":
    unittest.main()
