# NayVista Shield

> **AI-Assisted Web Security Assessment**  
> *Authorized, defensive web security assessment platform by NayVista Technologies.*

---

## Overview

**NayVista Shield** is an automated, defensive web security assessment platform engineered for web applications that you own or have explicit permission to test. Built with a unified architecture, it combines a high-performance Python security scanning engine, a Node.js/Express controller backend, a PostgreSQL/BullMQ data layer with local zero-config fallbacks, an AI explanation and prioritization engine, and a dark-mode cybersecurity SaaS dashboard.

### Dual-Interface Access
NayVista Shield supports two first-class interfaces powered by the **identical** Python scanning engine:
1. **Professional Web GUI**: Premium dark-mode dashboard (React 18 + Vite + TypeScript + Tailwind CSS + Lucide icons) with live 10-step progress, interactive circular score gauge, OWASP distribution charts, attack surface catalog, and printable PDF reports.
2. **Professional Terminal CLI**: High-performance CLI (`nayvista-shield`, `nshield`, `python -m scanner`) using Rich for colorized tables, step progress, security summary score cards, machine-readable JSON, and direct print-ready HTML exports.

### Core User Experience
- **Web**: Enter Target Website URL, confirm authorization checkbox, click **START SECURITY SCAN**.
- **CLI**: Run `nayvista-shield https://example.com` or `nshield https://example.com`.

---

## Important Security Boundaries

NayVista Shield is strictly an **authorized defensive audit tool**. It enforces:

- **Strict Target Scoping**: Only audits the exact submitted domain and same-origin URLs discovered during crawling. External links and cross-origin redirects are never followed.
- **SSRF Defense**: Rejects loopback addresses (`127.0.0.1`, `localhost`), link-local metadata endpoints (`169.254.169.254`), and private RFC1918 IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Zero Attack Payloads**: Defensive assessment only. Never attempts credential attacks, brute forcing, password cracking, account takeover, authentication bypassing, or destructive testing.
- **Strict Privacy**: Never displays, stores, or logs passwords, API keys, tokens, session cookies, or authorization headers. Evidence is automatically sanitized with `[REDACTED]`.
- **Sensitive File Probing**: When checking `.git/HEAD` or `.env`, it checks HTTP headers and status only. Contents are never downloaded, saved, printed, or passed to AI.
- **Conservative Crawler Limits**: Maximum 3 concurrent requests, 100ms throttle between requests, crawl depth limit of 2, 15 pages maximum, and a 2MB response size limit.
- **Robots.txt Adherence**: Respects `Disallow` directives for crawl paths.

---

## Architecture & Project Structure

```
E:\tool\
├── nayvista-shield.cmd           # Windows launcher wrapper for nayvista-shield
├── nayvista-shield.bat           # Windows batch wrapper for nayvista-shield
├── nayvista-shield               # Unix/Linux shell wrapper for nayvista-shield
├── nshield.cmd                   # Windows launcher wrapper for nshield short alias
├── nshield.bat                   # Windows batch wrapper for nshield short alias
├── nshield                       # Unix/Linux shell wrapper for nshield short alias
├── setup.py                      # Python package setup with console_scripts entrypoints
├── pyproject.toml                # PEP 517 build config
├── requirements.txt              # Scanner dependencies (httpx, beautifulsoup4, rich)
├── README.md                     # Documentation & operational guide
├── .env.example                  # Environment variable template
│
├── scanner/                      # Python Core Scanning Engine
│   ├── __init__.py
│   ├── __main__.py               # python -m scanner entrypoint
│   ├── config.py                 # Conservative limits, timeouts, and user agent
│   ├── scope.py                  # Strict scoping & SSRF validation
│   ├── crawler.py                # Safe, conservative same-origin crawler
│   ├── findings.py               # Canonical finding model, secret sanitization & deduplication
│   ├── scoring.py                # Security score (0-100), letter grade (A-F), and risk evaluation
│   ├── engine.py                 # Core ScannerEngine class & scan() API
│   ├── orchestrator.py           # Compatibility pipeline coordinator
│   ├── report.py                 # Standalone JSON & print-ready HTML report generators
│   ├── cli.py                    # Rich interactive terminal interface
│   ├── scanner_cli.py            # Headless entrypoint for backend IPC
│   ├── modules/                  # 10 Modular Security Analyzers
│   │   ├── headers.py            # 1. CSP, HSTS, X-Content-Type, Permissions-Policy
│   │   ├── cookies.py            # 2. Secure, HttpOnly, SameSite flags & domain scope
│   │   ├── tls.py                # 3. Certificate expiration, trust, legacy TLSv1.0/1.1
│   │   ├── cors.py               # 4. Origin reflection, wildcard with credentials
│   │   ├── information.py        # 5. Server banners, X-Powered-By, safe status probes (.git, .env)
│   │   ├── methods.py            # 6. OPTIONS query, dangerous verbs (TRACE/TRACK)
│   │   ├── redirects.py          # 7. HTTP->HTTPS upgrade, open redirect URL parameters
│   │   ├── content.py            # 8. Cleartext forms, insecure password inputs, SRI
│   │   ├── surface.py            # 9. Attack surface inventory (endpoints, forms, params)
│   │   └── technology.py         # 10. Passive technology & CMS fingerprinting
│   └── tests/
│       ├── mock_target_server.py # Built-in local mock vulnerable web server
│       └── test_scanner_pipeline.py # Unit and integration test suite
│
├── backend/                      # Node.js + Express + TypeScript Controller
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts              # Server startup & bootstrap
│   │   ├── server.ts             # Express app setup, CORS, JSON middleware
│   │   ├── config.ts             # Environment configuration
│   │   ├── routes/scans.ts       # REST endpoints (/api/scans, /report, /cancel)
│   │   ├── services/
│   │   │   ├── urlValidator.ts   # Server-side validation & SSRF filter
│   │   │   ├── scannerService.ts # Process executor & real-time IPC progress streamer
│   │   │   ├── queueService.ts   # BullMQ queue with in-process async fallback
│   │   │   └── reportService.ts  # JSON and printable HTML report generators
│   │   ├── db/
│   │   │   ├── schema.sql        # PostgreSQL DDL
│   │   │   └── index.ts          # Storage adapter (PostgreSQL + resilient local fallback)
│   │   ├── ai/                   # AI Analysis Layer (Heuristic fallback + Gemini/OpenAI)
│   │   │   ├── aiService.ts
│   │   │   └── providers/
│   │   └── types/index.ts        # Shared TypeScript data contracts
│   └── tests/
│       ├── validator.test.ts     # URL and SSRF validation unit tests
│       └── api.test.ts           # REST API integration tests
│
└── frontend/                     # React 18 + Vite + TypeScript + Tailwind CSS
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    ├── src/
    │   ├── main.tsx
    │   ├── App.tsx               # View coordinator & state manager
    │   ├── api.ts                # REST API client
    │   ├── types.ts              # Frontend interfaces
    │   └── components/
    │       ├── Header.tsx        # Navigation header & branding
    │       ├── ScanForm.tsx      # Target input & authorization confirmation
    │       ├── ScanProgress.tsx  # Live 10-step progress indicator
    │       ├── DashboardOverview.tsx # Metrics, score gauge & AI summaries
    │       ├── ScoreGauge.tsx    # SVG security score circular gauge
    │       ├── FindingCard.tsx   # Expandable finding card with remediation
    │       ├── FindingsList.tsx  # Filterable findings by severity and OWASP
    │       ├── SurfaceInventoryView.tsx # Attack surface & technology inventory
    │       ├── ScanHistory.tsx   # Historical audit table
    │       └── ReportModal.tsx   # JSON and HTML report previewer
    └── dist/                     # Production build bundles
```

---

## 10-Stage Assessment Sequence

Both the Web GUI and Terminal CLI execute and display the exact 10-stage evaluation pipeline:

| Step | Phase Name | Description |
|---|---|---|
| `[1/10]` | **Target validation** | Normalizes target URL, validates DNS, and enforces SSRF/origin boundaries. |
| `[2/10]` | **HTTPS/TLS analysis** | Inspects certificate validity, trust chain, expiration, and legacy protocols. |
| `[3/10]` | **Security headers** | Conservative same-origin crawling and analysis of CSP, HSTS, and X-Content-Type. |
| `[4/10]` | **Cookie security** | Audits `Secure`, `HttpOnly`, and `SameSite` flags while redacting values. |
| `[5/10]` | **CORS analysis** | Probes origin reflection, wildcard `*` with credentials, and `null` trust. |
| `[6/10]` | **Redirect analysis** | Analyzes HTTP->HTTPS upgrade, redirect loops, and open redirect parameters. |
| `[7/10]` | **Content analysis** | Checks for forms submitting over HTTP, unencrypted password inputs, and SRI. |
| `[8/10]` | **Attack-surface inventory** | Catalogs accessible endpoints, parameters, and form input structures. |
| `[9/10]` | **Technology detection** | Fingerprints servers, frameworks, and CMS libraries passively. |
| `[10/10]` | **Risk analysis** | Deduplicates findings, computes 0–100 security score, and assigns letter grade. |

---

## Getting Started

### Prerequisites
- **Node.js**: v18 or higher (tested on Node v24.18.0)
- **Python**: v3.10 or higher (tested on Python 3.14) with `pip`
- *Optional*: PostgreSQL and Redis (the system includes automatic, zero-configuration local fallbacks)

### 1. Install Dependencies & Package
From the repository root:

```bash
# Install Python package in editable mode
py -m pip install -e .

# Install backend dependencies
cd backend && npm install

# Install frontend dependencies
cd ../frontend && npm install
```

### 2. Environment Configuration
Copy `.env.example` to `.env` in the root:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `5000` | Backend API port |
| `DATABASE_URL` | No | *(Local fallback)* | PostgreSQL connection string |
| `REDIS_URL` | No | *(In-process queue)* | Redis connection string for BullMQ |
| `PYTHON_BIN` | No | `py` (Windows) / `python3` | Python binary command |
| `GEMINI_API_KEY` | No | *(Heuristic AI)* | Google Gemini API key for AI explanations |
| `OPENAI_API_KEY` | No | *(Heuristic AI)* | OpenAI API key for AI explanations |
| `ALLOW_LOCAL_TARGETS` | No | `0` | Set to `1` only for running internal test servers |

---

## Terminal CLI Usage

NayVista Shield provides a standalone terminal CLI that works across Windows, Linux, Kali Linux, and Termux:

```bash
# Standard interactive scan with Rich formatting
nayvista-shield https://example.com

# Using the short alias
nshield https://example.com

# Using the Python module fallback
python -m scanner https://example.com

# Display help or version
nayvista-shield --help
nayvista-shield --version

# Machine-readable JSON output
nayvista-shield https://example.com --json

# Direct HTML audit report generation
nayvista-shield https://example.com --html-report audit_report.html

# Silent / quiet mode
nayvista-shield https://example.com --quiet --html-report report.html

# Audit local test endpoints (for authorized offline development only)
nayvista-shield http://127.0.0.1:8999 --allow-local
```

---

## Web GUI Usage

Start the development servers:

**Start Backend (Terminal 1):**
```bash
cd backend
npm run dev
# API running on http://127.0.0.1:5000
```

**Start Frontend (Terminal 2):**
```bash
cd frontend
npm run dev
# Dashboard running on http://localhost:3000
```

Open **http://localhost:3000** in your browser.

---

## Running Tests

NayVista Shield includes automated unit, integration, and end-to-end tests that run offline without touching third-party websites:

### 1. Python Scanner Test Suite
```bash
py -m unittest discover -s scanner/tests -p "test_*.py" -v
```

### 2. Backend Vitest Suite
```bash
cd backend
npm test
```

### 3. End-to-End System Test
```bash
node tests/e2e_verification.mjs
```

### 4. Production Builds
```bash
# Backend TypeScript
cd backend && npm run build

# Frontend Bundle
cd ../frontend && npm run build
```

---

## REST API Reference

- `POST /api/scans`: Initiates an authorized assessment (`{ "target": "https://example.com", "authorized": true }`).
- `GET /api/scans/:id`: Returns live progress step and status (`pending`, `running`, `completed`, `failed`).
- `GET /api/scans/:id/findings`: Returns normalized findings with optional `?severity=HIGH` filter.
- `GET /api/scans/:id/report?format=html|json`: Returns JSON or print-ready HTML audit report.
- `POST /api/scans/:id/cancel`: Cancels an in-flight assessment.
- `GET /api/scans`: Returns historical audit records.

---

## Known Limitations & Boundaries

1. **Unauthenticated Scoping**: Operates strictly unauthenticated in the MVP. It catalogs forms, inputs, and password fields defensively without attempting credential submission or brute forcing.
2. **Static DOM & Regex Analysis**: Inspects HTML responses via BeautifulSoup and HTTP headers without executing client-side JavaScript via a full headless browser.
3. **SSRF Rules in Production**: Refuses to audit `localhost`, `127.0.0.1`, RFC1918 subnets, or `169.254.169.254` unless `ALLOW_LOCAL_TARGETS=1` is explicitly configured for offline test harnesses.
