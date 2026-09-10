"""
NayVista Shield - Comprehensive CLI Automated Test Suite
Verifies:
1. Direct URL mode
2. Pure JSON mode (strictly valid JSON in stdout)
3. HTML report export
4. SSRF and scope error exit codes
5. Terminal width adaptability (80, 100, 120, 160 cols)
6. Persistent scan history and target origin grouping
7. System readiness checks
"""

import sys
import os
import json
import subprocess
import unittest
from typing import Dict, Any

# Ensure project root is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from scanner.cli.theme import format_severity
from scanner.cli.terminal import strip_ansi, get_terminal_width, make_box_top, make_box_bottom, format_box_row, wrap_text_lines
from scanner.cli.views.startup import check_system_readiness
from scanner.cli.history import save_scan, load_history, get_targets_history, get_scan, delete_scan

class TestNayVistaShieldCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start local mock vulnerable server
        from scanner.tests.mock_target_server import MockTestServer
        import socket, time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        cls.mock_port = sock.getsockname()[1]
        sock.close()
        cls.mock_server = MockTestServer(port=cls.mock_port)
        cls.mock_server.start()
        cls.mock_url = f"http://127.0.0.1:{cls.mock_port}"
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "mock_server") and cls.mock_server:
            cls.mock_server.stop()

    def test_system_readiness(self):
        """Verifies actual subsystem modules are ready and reported."""
        readiness = check_system_readiness()
        self.assertIn("CORE ENGINE", readiness)
        self.assertIn("SCOPE GUARD", readiness)
        self.assertIn("TLS ANALYZER", readiness)
        self.assertIn("FINDING ENGINE", readiness)
        self.assertIn("REPORT ENGINE", readiness)
        for comp, ready in readiness.items():
            self.assertTrue(ready, f"Component {comp} failed readiness check")

    def test_json_mode_purity(self):
        """CRITICAL: Verifies that --json outputs ONLY pure valid JSON to stdout."""
        cmd = [sys.executable, "-m", "scanner", self.mock_url, "--json", "--allow-local", "--yes"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root_dir)
        self.assertEqual(proc.returncode, 0, f"JSON mode failed with stderr: {proc.stderr}")

        stdout_raw = proc.stdout.strip()
        self.assertTrue(stdout_raw.startswith("{"), "stdout must start directly with JSON '{'")
        self.assertTrue(stdout_raw.endswith("}"), "stdout must end directly with JSON '}'")

        # Must parse cleanly as JSON
        try:
            parsed = json.loads(stdout_raw)
        except Exception as e:
            self.fail(f"stdout is not valid JSON: {e}\nRaw output was:\n{stdout_raw[:200]}")

        self.assertIn("findings", parsed)
        self.assertIn("posture", parsed)
        self.assertIn("scoring", parsed)

    def test_direct_mode_with_html_report(self):
        """Verifies direct target execution and HTML report generation."""
        report_file = os.path.join(root_dir, "test_direct_report.html")
        if os.path.exists(report_file):
            os.remove(report_file)

        try:
            cmd = [sys.executable, "-m", "scanner", self.mock_url, "--html-report", report_file, "--allow-local", "--yes"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root_dir)
            self.assertEqual(proc.returncode, 0, f"Direct scan failed: {proc.stderr}")

            self.assertTrue(os.path.exists(report_file), "HTML report file was not created")
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("NAYVISTA SHIELD", content)
            self.assertIn("127.0.0.1", content)
        finally:
            if os.path.exists(report_file):
                os.remove(report_file)

    def test_ssrf_blocking_exit_code(self):
        """Verifies SSRF target is blocked and returns exit code 2."""
        cmd = [sys.executable, "-m", "scanner", "http://169.254.169.254/latest/meta-data", "--yes"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root_dir)
        self.assertEqual(proc.returncode, 2, "SSRF target must exit with code 2")

    def test_scope_error_exit_code(self):
        """Verifies invalid scheme returns exit code 1."""
        cmd = [sys.executable, "-m", "scanner", "ftp://example.com", "--yes"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=root_dir)
        self.assertEqual(proc.returncode, 1, "Unsupported scheme must exit with code 1")

    def test_terminal_formatting_and_widths(self):
        """Verifies box rendering and text wrapping across 80, 100, 120, 160 column widths."""
        test_text = "This is a long finding title description for NayVista Shield testing how responsive layout wraps."
        for width in (60, 80, 100, 120, 160):
            top = make_box_top(width, title="TEST BOX")
            bot = make_box_bottom(width)
            row = format_box_row(test_text, width)
            wrapped = wrap_text_lines(test_text, width - 6)

            self.assertEqual(len(strip_ansi(top)), width)
            self.assertEqual(len(strip_ansi(bot)), width)
            self.assertEqual(len(strip_ansi(row)), width)
            for w_line in wrapped:
                self.assertLessEqual(len(w_line), width - 6)

    def test_persistent_history_and_target_grouping(self):
        """Verifies saving, retrieving, grouping, and deleting scans in persistent history."""
        mock_result = {
            "id": "cli-test-scan-12345",
            "target": "http://cli-test-target.example:8443",
            "hostname": "cli-test-target.example",
            "port": 8443,
            "scheme": "http",
            "posture": "ASSESSED",
            "pages_scanned": 3,
            "duration_seconds": 1.25,
            "scoring": {
                "score": 75,
                "grade": "C",
                "risk_level": "MEDIUM",
                "counts": {"MEDIUM": 2, "LOW": 1},
            },
            "findings": [
                {
                    "id": "NS-001122334455",
                    "title": "Missing CSP Header",
                    "severity": "MEDIUM",
                    "owasp": "A05:2021",
                }
            ],
        }

        # Save scan
        saved_id = save_scan(mock_result)
        self.assertEqual(saved_id, "cli-test-scan-12345")

        # Load history
        history = load_history()
        found = any(s.get("id") == saved_id for s in history)
        self.assertTrue(found, "Saved scan not found in history")

        # Get specific scan
        rec = get_scan(saved_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.get("score"), 75)
        self.assertEqual(rec.get("grade"), "C")

        # Target grouping
        groups = get_targets_history()
        origin = "cli-test-target.example:8443"
        self.assertIn(origin, groups)
        self.assertEqual(groups[origin][0].get("id"), saved_id)

        # Cleanup
        deleted = delete_scan(saved_id)
        self.assertTrue(deleted)
        self.assertIsNone(get_scan(saved_id))

if __name__ == "__main__":
    unittest.main()
