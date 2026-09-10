"""
SentinelScan - Local Mock Vulnerable Web Server for Integration Testing
A lightweight, completely local and self-contained HTTP server
configured with intentional, non-destructive security misconfigurations:
- Missing CSP, HSTS, X-Content-Type-Options
- Missing Secure/HttpOnly flags on cookie
- CORS reflection
- Server banner with version
- Form submitting over HTTP with password field
- Simulated .git/HEAD and .env exposure check endpoints
- Links to same-origin pages
"""

import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

class MockVulnerableHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Unix) OpenSSL/1.1.1"
    sys_version = ""

    def log_message(self, format, *args):
        # Suppress noisy standard output logs during test runs
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        origin = self.headers.get("Origin")

        # Endpoint 1: .git/HEAD simulation
        if self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return

        # Endpoint 2: .env simulation
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"APP_KEY=base64:mockedkey1234567890=\nDB_PASSWORD=mockedpassword\n")
            return

        # Endpoint 3: Subpage /dashboard
        if self.path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = """<!DOCTYPE html>
            <html>
            <head><title>Dashboard</title></head>
            <body>
                <h1>Internal User Portal</h1>
                <a href="/login">Return to Login</a>
            </body>
            </html>"""
            self.wfile.write(body.encode("utf-8"))
            return

        # Endpoint 4: Login page with password field
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = """<!DOCTYPE html>
            <html>
            <head><title>Login</title></head>
            <body>
                <form action="http://localhost/api/auth" method="POST">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button type="submit">Sign In</button>
                </form>
            </body>
            </html>"""
            self.wfile.write(body.encode("utf-8"))
            return

        # Phase 2 Endpoint 5: WAF 403 Forbidden probe
        if self.path == "/waf-block":
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "cloudflare")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden - Access Denied by WAF</h1></body></html>")
            return

        # Phase 2 Endpoint 6: Rate Limiting 429 probe
        if self.path == "/rate-limit":
            self.send_response(429)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Retry-After", "60")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>429 Too Many Requests</h1></body></html>")
            return

        # Phase 2 Endpoint 7: Server Error 500 probe
        if self.path == "/server-error":
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>500 Internal Server Error</h1></body></html>")
            return

        # Phase 2 Endpoint 8: SSRF redirect attempt
        if self.path == "/ssrf-redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return

        # Phase 2 Endpoint 9: Redirect hop 1
        if self.path == "/hop1":
            self.send_response(302)
            self.send_header("Location", "/hop2")
            self.end_headers()
            return

        # Phase 2 Endpoint 10: Redirect hop 2 (circular back to hop1)
        if self.path == "/hop2":
            self.send_response(302)
            self.send_header("Location", "/hop1")
            self.end_headers()
            return

        # Phase 2 Endpoint 11: Large payload (>2.5MB)
        if self.path == "/large-file":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            chunk = b"A" * 1024 * 1024  # 1MB chunk
            for _ in range(3):  # 3MB total
                self.wfile.write(chunk)
            return

        # Phase 2 Endpoint 12: Binary asset image
        if self.path == "/logo.png":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")
            return

        # Root Endpoint /
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        # Insecure cookie (no Secure, no HttpOnly, no SameSite)
        self.send_header("Set-Cookie", "session_token=mock_secret_session_token_12345; Path=/")

        # Insecure CORS Origin Reflection if Origin header provided
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

        self.end_headers()

        body = """<!DOCTYPE html>
        <html>
        <head>
            <title>Mock Vulnerable App</title>
            <meta name="generator" content="WordPress 5.8" />
        </head>
        <body>
            <h1>Welcome to Mock Test Platform</h1>
            <p>Authorized scanning test harness.</p>
            <a href="/dashboard">View Dashboard</a>
            <a href="/login">User Login</a>
            <a href="https://unrelated-third-party.com" target="_blank">External Partner</a>
            <script src="https://cdn.example.com/unpinned-library.js"></script>
        </body>
        </html>"""
        self.wfile.write(body.encode("utf-8"))

class MockTestServer:
    def __init__(self, host="127.0.0.1", port=8999):
        self.host = host
        self.port = port
        self.server = HTTPServer((self.host, self.port), MockVulnerableHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.2)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

if __name__ == "__main__":
    port = 8999
    server = MockTestServer(port=port)
    server.start()
    print(f"Mock Vulnerable Server listening at http://127.0.0.1:{port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("Server stopped.")
