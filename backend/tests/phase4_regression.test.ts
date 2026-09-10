import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../src/server.js';
import { db } from '../src/db/index.js';
import { comparisonService } from '../src/services/comparisonService.js';
import { reportService } from '../src/services/reportService.js';
import { Server } from 'http';
import { ScanRecord, Finding } from '../src/types/index.js';

describe('NayVista Shield Phase 4 - Finding Intelligence, Comparison & Tenant Security', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    await db.init();
    const app = createServer();
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr: any = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  describe('1. Deterministic Scan Comparison & Lifecycle Rules', () => {
    const scanA: ScanRecord = {
      id: 'scan-101',
      tenant_id: 'default',
      target_url: 'https://example.com/',
      target_hostname: 'example.com',
      target_scheme: 'https',
      target_port: 443,
      authorized: true,
      status: 'completed',
      posture: 'ASSESSED',
      security_score: 75,
      grade: 'C',
      risk_level: 'MEDIUM',
      pages_scanned: 5,
      duration_seconds: 4.2,
      started_at: '2026-09-01T10:00:00Z',
      findings: [
        {
          id: 'NS-csp-missing-123',
          scanner: 'headers',
          title: 'Content Security Policy (CSP) Missing',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          status: 'OPEN',
          category: 'Security Misconfiguration',
          owasp: 'A05:2021-Security Misconfiguration',
          cwe: 'CWE-693',
          url: 'https://example.com/',
          affected_component: 'Content-Security-Policy',
          description: 'No CSP',
          evidence: 'Missing header',
          impact: 'XSS exposure',
          remediation: 'Add CSP',
          references: [],
          first_seen: '2026-09-01T10:00:00Z',
          affected_urls: ['https://example.com/'],
        },
        {
          id: 'NS-cookie-insecure-456',
          scanner: 'cookies',
          title: "Cookie 'session' Missing 'Secure' Flag",
          severity: 'HIGH',
          confidence: 'HIGH',
          status: 'OPEN',
          category: 'Cryptographic Failures',
          owasp: 'A02:2021-Cryptographic Failures',
          cwe: 'CWE-614',
          url: 'https://example.com/',
          affected_component: 'Set-Cookie: session',
          description: 'No secure flag',
          evidence: 'session=[REDACTED]; Path=/',
          impact: 'Cleartext interception',
          remediation: 'Add Secure flag',
          references: [],
          first_seen: '2026-09-01T10:00:00Z',
          affected_urls: ['https://example.com/'],
        },
      ],
      inventory: {
        total_pages: 5,
        endpoints: ['/', '/about', '/login'],
        parameters: ['q'],
        forms_count: 1,
        forms: [{ page_url: '/login', action: '/login', method: 'POST', fields: [] }],
        api_endpoints: [],
      },
    };

    it('identifies persistent, resolved, and new findings when target is successfully assessed', () => {
      // In Scan B: Cookie is fixed (resolved), CSP is still missing (persistent), and HSTS is newly missing (new)
      const scanB: ScanRecord = {
        id: 'scan-102',
        tenant_id: 'default',
        target_url: 'https://example.com/',
        target_hostname: 'example.com',
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        status: 'completed',
        posture: 'ASSESSED',
        security_score: 85,
        grade: 'B',
        risk_level: 'LOW',
        pages_scanned: 5,
        duration_seconds: 3.8,
        started_at: '2026-09-05T10:00:00Z',
        findings: [
          scanA.findings[0], // CSP missing persists
          {
            id: 'NS-hsts-missing-789',
            scanner: 'headers',
            title: 'HSTS Header Missing',
            severity: 'LOW',
            confidence: 'HIGH',
            status: 'OPEN',
            category: 'Cryptographic Failures',
            owasp: 'A02:2021-Cryptographic Failures',
            cwe: 'CWE-319',
            url: 'https://example.com/',
            affected_component: 'Strict-Transport-Security',
            description: 'No HSTS',
            evidence: 'Missing header',
            impact: 'Downgrade risk',
            remediation: 'Add HSTS',
            references: [],
            first_seen: '2026-09-05T10:00:00Z',
            affected_urls: ['https://example.com/'],
          },
        ],
        inventory: {
          total_pages: 6,
          endpoints: ['/', '/about', '/login', '/contact'],
          parameters: ['q', 'page'],
          forms_count: 2,
          forms: [],
          api_endpoints: [],
        },
      };

      const comp = comparisonService.compareScans(scanA, scanB);
      expect(comp.summary.persistent_count).toBe(1);
      expect(comp.summary.resolved_count).toBe(1);
      expect(comp.summary.new_count).toBe(1);
      expect(comp.summary.regressed_count).toBe(0);

      expect(comp.findings.persistent[0].id).toBe('NS-csp-missing-123');
      expect(comp.findings.resolved[0].id).toBe('NS-cookie-insecure-456');
      expect(comp.findings.new[0].id).toBe('NS-hsts-missing-789');

      // Deltas
      expect(comp.delta.score).toBe(10); // 75 -> 85
      expect(comp.delta.grade_changed).toBe(true);
      expect(comp.delta.attack_surface_diff.endpoints).toBe(1);
    });

    it('DOES NOT mark findings resolved when target scan was RESTRICTED (WAF blocked)', () => {
      const restrictedScanB: ScanRecord = {
        ...scanA,
        id: 'scan-103',
        posture: 'RESTRICTED',
        security_score: 70,
        grade: 'C',
        pages_scanned: 1,
        findings: [], // Found nothing because WAF blocked access!
      };

      const comp = comparisonService.compareScans(scanA, restrictedScanB);
      // Missing findings MUST NOT be marked resolved because target was not successfully crawled!
      expect(comp.summary.resolved_count).toBe(0);
      expect(comp.summary.persistent_count).toBe(2);
    });

    it('DOES NOT mark findings resolved when target scan was DEGRADED (5xx/TLS error)', () => {
      const degradedScanB: ScanRecord = {
        ...scanA,
        id: 'scan-104',
        posture: 'DEGRADED',
        security_score: 60,
        grade: 'D',
        pages_scanned: 1,
        findings: [],
      };

      const comp = comparisonService.compareScans(scanA, degradedScanB);
      expect(comp.summary.resolved_count).toBe(0);
      expect(comp.summary.persistent_count).toBe(2);
    });

    it('identifies REGRESSED findings if issue was seen in earlier history', () => {
      const scanC: ScanRecord = {
        id: 'scan-105',
        tenant_id: 'default',
        target_url: 'https://example.com/',
        target_hostname: 'example.com',
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        status: 'completed',
        posture: 'ASSESSED',
        security_score: 70,
        grade: 'C',
        risk_level: 'MEDIUM',
        pages_scanned: 5,
        duration_seconds: 4.0,
        started_at: '2026-09-10T10:00:00Z',
        findings: [
          scanA.findings[1], // Cookie insecure returned!
        ],
      };

      // Base is Scan B (which did not have the cookie bug), but Scan A (prior) had it!
      const scanB: ScanRecord = { ...scanA, id: 'scan-102', findings: [] };
      const comp = comparisonService.compareScans(scanB, scanC, [scanA]);

      expect(comp.summary.regressed_count).toBe(1);
      expect(comp.findings.regressed[0].id).toBe('NS-cookie-insecure-456');
      expect(comp.findings.regressed[0].status).toBe('RECURRED');
    });
  });

  describe('2. Report Secret Sanitization Layer', () => {
    it('unconditionally redacts all tokens, cookies, AWS keys, and passwords in JSON and HTML reports', () => {
      const dirtyScan: ScanRecord = {
        id: 'scan-sec-1',
        target_url: 'https://example.com',
        target_hostname: 'example.com',
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        status: 'completed',
        posture: 'ASSESSED',
        security_score: 80,
        grade: 'B',
        risk_level: 'LOW',
        pages_scanned: 2,
        duration_seconds: 2.5,
        started_at: '2026-09-10T10:00:00Z',
        findings: [],
      };

      const leakFindings: Finding[] = [
        {
          id: 'f-leak-1',
          scanner: 'test',
          title: 'Sensitive Leak Finding',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'Sensitive Data',
          owasp: 'A05:2021',
          url: 'https://example.com',
          affected_component: 'Headers',
          evidence: "Authorization: Bearer my_top_secret_jwt_token_999; Set-Cookie: admin_sid=super_secret_cookie_val_888; api_key = 'AKIA1234567890ABCDEF'; password='unmasked_db_pass';",
          description: 'Bearer secret_desc_token_abc and password=secret_password_123',
          impact: 'Exposure',
          remediation: 'Clean secrets',
          references: [],
          affected_urls: ['https://example.com'],
        },
      ];

      const json = reportService.generateJsonReport(dirtyScan, leakFindings);
      const jsonStr = JSON.stringify(json);
      expect(jsonStr).not.toContain('my_top_secret_jwt_token_999');
      expect(jsonStr).not.toContain('super_secret_cookie_val_888');
      expect(jsonStr).not.toContain('AKIA1234567890ABCDEF');
      expect(jsonStr).not.toContain('unmasked_db_pass');
      expect(jsonStr).not.toContain('secret_desc_token_abc');
      expect(jsonStr).not.toContain('secret_password_123');
      expect(jsonStr).toContain('[REDACTED]');

      const html = reportService.generateHtmlReport(dirtyScan, leakFindings);
      expect(html).not.toContain('my_top_secret_jwt_token_999');
      expect(html).not.toContain('super_secret_cookie_val_888');
      expect(html).not.toContain('AKIA1234567890ABCDEF');
      expect(html).not.toContain('unmasked_db_pass');
      expect(html).not.toContain('secret_desc_token_abc');
      expect(html).not.toContain('secret_password_123');
      expect(html).toContain('[REDACTED]');
      expect(html).toContain('@media print');
    });
  });

  describe('3. Multi-Tenant Isolation & IDOR Protection', () => {
    let tenantAScanId: string;
    let tenantBScanId: string;

    beforeAll(async () => {
      // Create scan for Tenant Alpha
      const resA = await fetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer alpha-secret-token',
        },
        body: JSON.stringify({ target: 'https://example.com', authorized: true }),
      });
      const dataA = await resA.json();
      tenantAScanId = dataA.scanId;

      // Create scan for Tenant Beta
      const resB = await fetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer beta-secret-token',
        },
        body: JSON.stringify({ target: 'https://example.com', authorized: true }),
      });
      const dataB = await resB.json();
      tenantBScanId = dataB.scanId;
    });

    it('Tenant Alpha can access their own scan', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}`, {
        headers: { 'Authorization': 'Bearer alpha-secret-token' },
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.scan.id).toBe(tenantAScanId);
    });

    it('Tenant Beta CANNOT access Tenant Alpha scan (IDOR Protection -> returns 404)', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}`, {
        headers: { 'Authorization': 'Bearer beta-secret-token' },
      });
      expect(res.status).toBe(404);
    });

    it('Tenant Beta CANNOT access Tenant Alpha report', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}/report`, {
        headers: { 'Authorization': 'Bearer beta-secret-token' },
      });
      expect(res.status).toBe(404);
    });

    it('Tenant Beta CANNOT access Tenant Alpha findings', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}/findings`, {
        headers: { 'Authorization': 'Bearer beta-secret-token' },
      });
      expect(res.status).toBe(404);
    });

    it('Tenant Beta CANNOT delete Tenant Alpha scan', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer beta-secret-token' },
      });
      expect(res.status).toBe(404);
    });

    it('Tenant Beta CANNOT compare with Tenant Alpha scan', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantBScanId}/compare/${tenantAScanId}`, {
        headers: { 'Authorization': 'Bearer beta-secret-token' },
      });
      expect(res.status).toBe(404);
    });

    it('Rejects header manipulation (Tenant Alpha token passing X-Tenant-ID for Beta -> 403)', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${tenantAScanId}`, {
        headers: {
          'Authorization': 'Bearer alpha-secret-token',
          'X-Tenant-ID': 'tenant-beta',
        },
      });
      expect(res.status).toBe(403);
    });

    it('Rejects malformed tenant identifier with control/SQL characters -> 400', async () => {
      const res = await fetch(`${baseUrl}/api/scans`, {
        headers: {
          'X-Tenant-ID': 'bad/tenant;drop table',
        },
      });
      expect(res.status).toBe(400);
    });
  });

  describe('4. Remediation Checklist & Status Updates', () => {
    let scanId: string;

    beforeAll(async () => {
      const scan: ScanRecord = {
        id: 'scan-remed-100',
        tenant_id: 'default',
        target_url: 'https://test-remed.example.com',
        target_hostname: 'test-remed.example.com',
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        status: 'completed',
        posture: 'ASSESSED',
        security_score: 90,
        grade: 'A',
        risk_level: 'LOW',
        pages_scanned: 1,
        duration_seconds: 1,
        started_at: new Date().toISOString(),
        findings: [
          {
            id: 'NS-finding-rem-1',
            scanner: 'headers',
            title: 'Sample Finding For Remediation',
            severity: 'LOW',
            confidence: 'HIGH',
            status: 'OPEN',
            category: 'Security Misconfiguration',
            owasp: 'A05:2021',
            cwe: 'CWE-693',
            url: 'https://test-remed.example.com',
            affected_component: 'Header',
            description: 'Test',
            evidence: 'Test',
            impact: 'Test',
            remediation: 'Fix it',
            references: [],
            affected_urls: ['https://test-remed.example.com'],
          },
        ],
      };
      await db.saveScan(scan);
      await db.saveFindings(scan.id, scan.findings);
      scanId = scan.id;
    });

    it('retrieves initial remediation checklist', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${scanId}/remediation`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.items.length).toBe(1);
      expect(data.items[0].state).toBe('OPEN');
    });

    it('updates remediation item state to IN_PROGRESS and COMPLETED', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${scanId}/remediation/NS-finding-rem-1`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'COMPLETED' }),
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.item.state).toBe('COMPLETED');
    });

    it('updates finding status to ACCEPTED_RISK', async () => {
      const res = await fetch(`${baseUrl}/api/scans/${scanId}/findings/NS-finding-rem-1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ACCEPTED_RISK' }),
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('ACCEPTED_RISK');

      // Verify persistence
      const fetchRes = await fetch(`${baseUrl}/api/scans/${scanId}/findings`);
      const findingsData = await fetchRes.json();
      expect(findingsData.findings[0].status).toBe('ACCEPTED_RISK');
    });
  });

  describe('5. Target History Grouping', () => {
    it('groups historical scans by normalized origin', async () => {
      const res = await fetch(`${baseUrl}/api/scans/targets/history`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(Array.isArray(data.targets)).toBe(true);
    });
  });
});
