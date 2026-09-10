"""
SentinelScan - Global Configuration Defaults
Defines conservative boundaries, timeouts, concurrency, and crawler limits.
"""

import os

# Application Metadata
APP_NAME = "NayVista Shield"
APP_TAGLINE = "AI-Assisted Web Security Assessment"
APP_COMPANY = "NayVista Technologies"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Authorized Defensive Web Security Assessment Platform"

# Conservative Crawler Boundaries
MAX_DEPTH = 2
MAX_PAGES = 15
MAX_CONCURRENCY = 3
REQUEST_THROTTLE_SECONDS = 0.1
RESPONSE_MAX_BYTES = 2 * 1024 * 1024  # 2MB
TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5

USER_AGENT = "NayVistaShield-Security-Auditor/1.0 (+https://nayvista.com/shield/bot)"

# Test / Development flag
ALLOW_LOCAL_TARGETS = os.environ.get("ALLOW_LOCAL_TARGETS", "").lower() in ("1", "true", "yes")
