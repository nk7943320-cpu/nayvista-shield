"""
NayVista Shield - Active / Authorized Testing Mode Unit & Integration Tests
Validates the complete active testing pipeline against local mock server:
- Mandatory authorization gate
- Active Request Controller limits and SSRF boundaries
- Bounded active modules execution
- Auditor-grade finding format (deterministic IDs, confidence, structured evidence)
- Graceful DNS reachability / limitation handling
"""

import unittest
import asyncio
from scanner.tests.mock_target_server import MockTestServer
from scanner.engine import ScannerEngine
from scanner.active.scope_policy import ScopePolicy, OutOfScopeError
from scanner.active.controller import ActiveRequestController
from scanner.scope import TargetSSRFBlockedError

class TestActiveMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockTestServer(port=8994)
        cls.server.start()
        cls.url = f"http://127.0.0.1:{cls.server.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_01_authorization_gate_enforcement(self):
        """Active mode must reject execution if authorized is False."""
        engine = ScannerEngine(
            target_url=self.url,
            allow_local=True,
            mode="ACTIVE / AUTHORIZED TESTING",
            authorized=False,
        )
        with self.assertRaises(PermissionError) as ctx:
            engine.scan()
        self.assertIn("authorization", str(ctx.exception).lower())

    def test_02_scope_policy_and_ssrf_protection(self):
        """ScopePolicy must reject cloud metadata and unauthorized origins."""
        # SSRF blocked on cloud metadata
        with self.assertRaises(TargetSSRFBlockedError):
            ScopePolicy("http://169.254.169.254/latest/meta-data/", allow_local=False)

        # Same origin validation
        policy = ScopePolicy(self.url, allow_local=True)
        self.assertTrue(policy.is_in_scope(f"{self.url}/dashboard"))
        self.assertFalse(policy.is_in_scope("https://evil-untrusted-site.com/"))
        self.assertFalse(policy.is_in_scope(f"{self.url}/logout"))

    def test_03_active_request_controller_safety(self):
        """ActiveRequestController must enforce method whitelisting and budgets."""
        async def run_test():
            policy = ScopePolicy(self.url, allow_local=True)
            controller = ActiveRequestController(
                scope_policy=policy,
                max_concurrency=2,
                max_total_requests=5,
                max_stage_requests=3,
            )
            controller.set_current_stage("test_stage")

            # Permitted method GET
            resp = await controller.request("GET", f"{self.url}/")
            self.assertIsNotNone(resp)
            self.assertEqual(resp.status_code, 200)

            # Prohibited method POST
            with self.assertRaises(ValueError):
                await controller.request("POST", f"{self.url}/")

            await controller.close()

        asyncio.run(run_test())

    def test_04_full_active_assessment_against_mock_target(self):
        """Execute complete active assessment against local mock server."""
        engine = ScannerEngine(
            target_url=self.url,
            allow_local=True,
            mode="ACTIVE / AUTHORIZED TESTING",
            authorized=True,
        )
        result = engine.scan()

        # Invariant checks
        self.assertEqual(result["mode"], "ACTIVE / AUTHORIZED TESTING")
        self.assertEqual(result["assessment_status"], "COMPLETED")
        self.assertIn("coverage", result)
        self.assertGreaterEqual(result["coverage"]["percentage"], 90)
        self.assertIn("stage_status", result)
        self.assertIn("findings", result)
        self.assertGreater(len(result["findings"]), 0)

        # Verify findings format
        for f in result["findings"]:
            self.assertTrue(f["id"].startswith("NS-"), f"Finding ID must start with NS-: {f['id']}")
            self.assertIn(f["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
            self.assertIn(f["confidence"], ("CONFIRMED", "LIKELY", "POTENTIAL", "NOT_CONFIRMED", "NOT_TESTABLE"))
            self.assertIn("structured_evidence", f)
            se = f["structured_evidence"]
            self.assertIn("test", se)
            self.assertIn("target", se)
            self.assertIn("expected", se)
            self.assertIn("observed", se)

        # Verify key expected detections from mock server
        titles = [f["title"] for f in result["findings"]]
        # 1. TRACE / OPTIONS method
        has_options = any("HTTP Methods" in t for t in titles)
        # 2. CORS reflection
        has_cors = any("CORS" in t for t in titles)
        # 3. Insecure cookie
        has_cookie = any("Cookie" in t for t in titles)
        # 4. Infrastructure exposure (.git/HEAD or .env)
        has_infra = any(".git" in t or ".env" in t or "Configuration" in t or "Repository" in t for t in titles)

        self.assertTrue(has_options, f"Expected dangerous HTTP methods finding. Got: {titles}")
        self.assertTrue(has_cors, f"Expected CORS finding. Got: {titles}")
        self.assertTrue(has_cookie, f"Expected cookie finding. Got: {titles}")
        self.assertTrue(has_infra, f"Expected infrastructure finding. Got: {titles}")

    def test_05_unreachable_target_handling(self):
        """Active assessment on unreachable domain must handle limitation gracefully."""
        unreachable_url = "https://unreachable-domain-nayvista-test-999.invalid"
        engine = ScannerEngine(
            target_url=unreachable_url,
            allow_local=False,
            mode="ACTIVE / AUTHORIZED TESTING",
            authorized=True,
        )
        result = engine.scan()

        self.assertEqual(result["mode"], "ACTIVE / AUTHORIZED TESTING")
        self.assertEqual(result["posture"], "LIMITED")
        self.assertEqual(result["assessment_status"], "COMPLETED_WITH_LIMITATIONS")
        self.assertIsNone(result["scoring"]["score"])
        self.assertTrue(result["is_limited"])
        self.assertTrue(any(l["code"] == "TARGET_DNS_FAILURE" for l in result["limitations"]))

if __name__ == "__main__":
    unittest.main()
