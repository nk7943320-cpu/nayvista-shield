import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../src/server.js';
import { db } from '../src/db/index.js';
import { validateTargetUrl, ValidationError } from '../src/services/urlValidator.js';
import { sanitizeLogString, logger } from '../src/utils/logger.js';
import { reportService } from '../src/services/reportService.js';
import { validateConfig, config } from '../src/config.js';
import { Server } from 'http';
import { ScanRecord, Finding } from '../src/types/index.js';

describe('NayVista Shield Security & Architecture Regression Tests', () => {
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

  describe('1. Authorization Gate', () => {
    it('rejects scan request when authorized is missing or false', async () => {
      const res = await fetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'https://example.com' }),
      });
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain('explicitly authorized');
    });

    it('rejects scan request when authorized is explicitly false', async () => {
      const res = await fetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'https://example.com', authorized: false }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe('2. SSRF Protection & Scheme Validation', () => {
    it('blocks private IPv4 addresses', async () => {
      await expect(validateTargetUrl('http://10.0.0.1', true)).rejects.toThrow('SSRF Protection');
      await expect(validateTargetUrl('http://192.168.1.1', true)).rejects.toThrow('SSRF Protection');
      await expect(validateTargetUrl('http://172.16.0.1', true)).rejects.toThrow('SSRF Protection');
    });

    it('blocks loopback and cloud metadata', async () => {
      await expect(validateTargetUrl('http://127.0.0.1', true)).rejects.toThrow('SSRF Protection');
      await expect(validateTargetUrl('http://169.254.169.254', true)).rejects.toThrow('SSRF Protection');
    });

    it('blocks IPv6 loopback and IPv4-mapped IPv6', async () => {
      await expect(validateTargetUrl('http://[::1]', true)).rejects.toThrow('SSRF Protection');
      await expect(validateTargetUrl('http://[::ffff:127.0.0.1]', true)).rejects.toThrow('SSRF Protection');
      await expect(validateTargetUrl('http://[::ffff:169.254.169.254]', true)).rejects.toThrow('SSRF Protection');
    });

    it('rejects unsafe URL schemes', async () => {
      await expect(validateTargetUrl('ftp://example.com', true)).rejects.toThrow("Unsupported scheme 'ftp'");
      await expect(validateTargetUrl('file:///etc/passwd', true)).rejects.toThrow("Unsupported scheme 'file'");
      await expect(validateTargetUrl('javascript:alert(1)', true)).rejects.toThrow();
      await expect(validateTargetUrl('data:text/html,test', true)).rejects.toThrow();
    });

    it('rejects command injection-shaped targets and control characters', async () => {
      await expect(validateTargetUrl('https://example.com; rm -rf /', true)).rejects.toThrow('Control or shell metacharacters');
      await expect(validateTargetUrl('https://example.com | cat /etc/passwd', true)).rejects.toThrow('Control or shell metacharacters');
      await expect(validateTargetUrl('https://example.com`id`', true)).rejects.toThrow('Control or shell metacharacters');
      await expect(validateTargetUrl('https://example.com\r\nInjected-Header: true', true)).rejects.toThrow('Control or shell metacharacters');
    });

    it('rejects excessively long URLs (> 2048 chars)', async () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(2100);
      await expect(validateTargetUrl(longUrl, true)).rejects.toThrow('maximum permitted length');
    });
  });

  describe('3. Secret Sanitization & Log Masking', () => {
    it('sanitizes Bearer tokens, cookies, AWS keys, and passwords', () => {
      const raw = "Authorization: Bearer secret_jwt_token_xyz; Set-Cookie: session_token=secret_val_123; api_key = 'AKIAIOSFODNN7EXAMPLE'; password = 'my_password'";
      const cleaned = sanitizeLogString(raw);
      expect(cleaned).toContain('Bearer [REDACTED]');
      expect(cleaned).toContain('[REDACTED]');
      expect(cleaned).not.toContain('secret_jwt_token_xyz');
      expect(cleaned).not.toContain('secret_val_123');
      expect(cleaned).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(cleaned).not.toContain('my_password');
    });

    it('sanitizes evidence before writing to reports', () => {
      const mockScan: ScanRecord = {
        id: 'scan-1',
        target_url: 'https://example.com',
        target_hostname: 'example.com',
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        status: 'completed',
        posture: 'ASSESSED',
        security_score: 85,
        grade: 'B',
        risk_level: 'MEDIUM',
        pages_scanned: 5,
        duration_seconds: 3.2,
        started_at: new Date().toISOString(),
        findings: [],
      };

      const mockFinding: Finding = {
        id: 'f-1',
        scanner: 'CookieScanner',
        title: 'Session Cookie Insecure',
        severity: 'HIGH',
        confidence: 'HIGH',
        category: 'Insecure Cookies',
        owasp: 'A05:2021-Security Misconfiguration',
        url: 'https://example.com',
        evidence: 'Set-Cookie: session_token=super_secret_cookie_token_9999; Path=/',
        description: 'Cookie missing flags',
        impact: 'Session hijacking',
        remediation: 'Set Secure and HttpOnly flags',
        affected_urls: ['https://example.com'],
      };

      const jsonReport = reportService.generateJsonReport(mockScan, [mockFinding]);
      expect(jsonReport.findings[0].evidence).not.toContain('super_secret_cookie_token_9999');
      expect(jsonReport.findings[0].evidence).toContain('[REDACTED]');

      const htmlReport = reportService.generateHtmlReport(mockScan, [mockFinding]);
      expect(htmlReport).not.toContain('super_secret_cookie_token_9999');
      expect(htmlReport).toContain('[REDACTED]');
    });
  });

  describe('4. Health Check Endpoints', () => {
    it('GET /health returns health metrics and component statuses', async () => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('ok');
      expect(data.components.api.status).toBe('ok');
      expect(data.components.database.status).toBe('ok');
      expect(data.components.queue.status).toBe('ok');
    });

    it('GET /api/health matches /health behavior', async () => {
      const res = await fetch(`${baseUrl}/api/health`);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('ok');
    });
  });

  describe('5. Configuration Validation', () => {
    it('validates config without throwing for valid setup', () => {
      expect(() => validateConfig()).not.toThrow();
    });
  });
});
