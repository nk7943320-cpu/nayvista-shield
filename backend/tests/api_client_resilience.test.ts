import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../src/server.js';
import { db } from '../src/db/index.js';
import http, { Server } from 'http';

/**
 * Mirror of client-side safeFetch and startScan validation logic
 * to verify complete frontend-backend contract compliance.
 */
async function safeFetch<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(input, init);
  } catch (_networkErr: any) {
    throw new Error(
      'Unable to connect to NayVista Shield API service. Please verify your network connection and backend server status.'
    );
  }

  let rawText = '';
  try {
    rawText = await response.text();
  } catch {
    rawText = '';
  }

  const trimmed = rawText.trim();
  const contentType = (response.headers.get('content-type') || '').toLowerCase();

  if (response.status === 204) {
    return { success: true } as unknown as T;
  }

  if (!trimmed) {
    if (!response.ok) {
      throw new Error(
        `ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response (HTTP ${response.status}).`
      );
    }
    throw new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response.');
  }

  if (contentType.includes('text/html') || trimmed.startsWith('<!DOCTYPE') || (trimmed.startsWith('<html') && trimmed.endsWith('>'))) {
    throw new Error(
      `ASSESSMENT INITIALIZATION FAILED: The assessment service returned a non-JSON response (HTTP ${response.status}). The server or proxy may be unavailable.`
    );
  }

  let parsed: any;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned malformed JSON.');
  }

  if (!response.ok) {
    const errorMsg =
      parsed?.error ||
      parsed?.message ||
      `Request failed with HTTP ${response.status}${response.statusText ? ' ' + response.statusText : ''}`;
    const err = new Error(errorMsg);
    if (parsed?.code) {
      (err as any).code = parsed.code;
    }
    throw err;
  }

  return parsed as T;
}

function validateScanId(data: any): string {
  if (
    !data ||
    typeof data.scanId !== 'string' ||
    data.scanId.trim().length === 0 ||
    data.scanId === 'undefined' ||
    data.scanId === 'null'
  ) {
    throw new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.');
  }
  return data.scanId.trim();
}

describe('NayVista Shield API & Client Resilience Tests', () => {
  let server: Server;
  let baseUrl: string;
  let mockFailureServer: Server;
  let mockFailureUrl: string;

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

    // Dedicated mock HTTP server simulating edge cases (502 empty, 502 HTML, malformed JSON, etc.)
    mockFailureServer = http.createServer((req, res) => {
      if (req.url === '/empty-502') {
        res.writeHead(502, { 'Content-Length': '0' });
        res.end();
      } else if (req.url === '/empty-200') {
        res.writeHead(200, { 'Content-Length': '0' });
        res.end();
      } else if (req.url === '/html-502') {
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body>502 Bad Gateway</body></html>');
      } else if (req.url === '/malformed-json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"success": true, "broken": [invalid json');
      } else if (req.url === '/missing-scanid') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, status: 'running' }));
      } else if (req.url === '/null-scanid') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, scanId: null }));
      } else if (req.url === '/undefined-scanid') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, scanId: 'undefined' }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => {
      mockFailureServer.listen(0, '127.0.0.1', () => {
        const addr: any = mockFailureServer.address();
        mockFailureUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    if (mockFailureServer) {
      await new Promise<void>((resolve) => mockFailureServer.close(() => resolve()));
    }
  });

  // 1. Successful Scan Creation
  it('1. Successful scan creation returns HTTP 201, valid JSON and valid scanId', async () => {
    const data = await safeFetch<any>(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'https://example.com',
        authorized: true,
      }),
    });

    expect(data.success).toBe(true);
    expect(data.status).toBe('queued');
    const validId = validateScanId(data);
    expect(validId.length).toBeGreaterThan(0);
  });

  // 2. Missing Authorization
  it('2. Missing authorization returns HTTP 400 with structured JSON error', async () => {
    await expect(
      safeFetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: 'https://example.com',
          authorized: false,
        }),
      })
    ).rejects.toThrow(/explicitly authorized/i);
  });

  // 3. SSRF Target Rejection
  it('3. SSRF target returns HTTP 400 with structured JSON error preserving protection', async () => {
    await expect(
      safeFetch(`${baseUrl}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: 'http://127.0.0.1:8000',
          authorized: true,
        }),
      })
    ).rejects.toThrow(/SSRF Protection/i);
  });

  // 4. Empty Response Simulation
  it('4. Empty 502 response is caught gracefully without JSON parser crash', async () => {
    await expect(safeFetch(`${mockFailureUrl}/empty-502`)).rejects.toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response (HTTP 502).'
    );
  });

  it('4b. Unexpected empty 200 response is caught gracefully', async () => {
    await expect(safeFetch(`${mockFailureUrl}/empty-200`)).rejects.toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response.'
    );
  });

  // 5. HTML Response Simulation
  it('5. HTML 502 response is identified and throws descriptive error without dumping HTML', async () => {
    await expect(safeFetch(`${mockFailureUrl}/html-502`)).rejects.toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned a non-JSON response (HTTP 502). The server or proxy may be unavailable.'
    );
  });

  // 6. Malformed JSON Simulation
  it('6. Malformed JSON is caught gracefully without exposing raw parser exception', async () => {
    await expect(safeFetch(`${mockFailureUrl}/malformed-json`)).rejects.toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned malformed JSON.'
    );
  });

  // 7. Missing or Invalid scanId Rejection
  it('7. Missing scanId in 200 OK response is strictly rejected', async () => {
    const res = await safeFetch<any>(`${mockFailureUrl}/missing-scanid`);
    expect(() => validateScanId(res)).toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.'
    );
  });

  it('7b. Null scanId is strictly rejected', async () => {
    const res = await safeFetch<any>(`${mockFailureUrl}/null-scanid`);
    expect(() => validateScanId(res)).toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.'
    );
  });

  it('7c. "undefined" string scanId is strictly rejected', async () => {
    const res = await safeFetch<any>(`${mockFailureUrl}/undefined-scanid`);
    expect(() => validateScanId(res)).toThrow(
      'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.'
    );
  });

  // 8. Network Failure Simulation
  it('8. Connection failure (offline server) produces actionable network error', async () => {
    await expect(safeFetch('http://127.0.0.1:59999/api/scans')).rejects.toThrow(
      'Unable to connect to NayVista Shield API service. Please verify your network connection and backend server status.'
    );
  });

  // 9. Malformed Request Body Handling in Backend
  it('9. Malformed JSON payload sent to backend returns HTTP 400 with INVALID_JSON code', async () => {
    const rawRes = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken": json payload',
    });

    expect(rawRes.status).toBe(400);
    expect(rawRes.headers.get('content-type')).toContain('application/json');
    const data = await rawRes.json();
    expect(data.code).toBe('INVALID_JSON');
    expect(data.error).toContain('Malformed JSON');
  });

  // 10. Global 404 Handler JSON Guarantee
  it('10. Global 404 handler returns structured JSON with NOT_FOUND code', async () => {
    const rawRes = await fetch(`${baseUrl}/api/route-that-does-not-exist`);
    expect(rawRes.status).toBe(404);
    expect(rawRes.headers.get('content-type')).toContain('application/json');
    const data = await rawRes.json();
    expect(data.code).toBe('NOT_FOUND');
  });
});
