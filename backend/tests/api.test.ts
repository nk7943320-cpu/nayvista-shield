import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../src/server.js';
import { db } from '../src/db/index.js';
import { Server } from 'http';

describe('NayVista Shield API Integration Tests', () => {
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

  it('GET /api/health returns ok', async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
    expect(data.service).toBe('NayVista Shield API');
  });

  it('POST /api/scans rejects without authorization', async () => {
    const res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'https://example.com',
        authorized: false,
      }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toContain('explicitly authorized');
  });

  it('POST /api/scans rejects SSRF target', async () => {
    const res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'http://127.0.0.1:8000',
        authorized: true,
      }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toContain('SSRF Protection');
  });

  it('POST /api/scans rejects attack simulation mode with 400', async () => {
    const res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'https://example.com',
        authorized: true,
        mode: 'ATTACK SIMULATION',
      }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toContain('ATTACK SIMULATION mode is disabled');
  });

  it('POST /api/scans accepts defensive mode and sets DEFENSIVE / SAFE', async () => {
    const res = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'https://example.com',
        authorized: true,
        mode: 'DEFENSIVE / SAFE',
      }),
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.mode).toBe('DEFENSIVE / SAFE');
    expect(data.scanId).toBeDefined();
  });

  it('GET /api/scans returns scan history list', async () => {
    const res = await fetch(`${baseUrl}/api/scans`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(Array.isArray(data.scans)).toBe(true);
  });
});
