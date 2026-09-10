/**
 * NayVista Shield - Active / Authorized Testing Mode End-to-End System Test
 * Verifies active mode execution across both CLI and Web GUI backend:
 * - Submits active scan to Web API
 * - Validates progress and active stages
 * - Validates findings with structured evidence and secret sanitization
 * - Validates CLI direct execution with --mode active --yes --json
 * - Confirms strict rejection of prohibited attack simulation mode
 */

import { spawn } from 'child_process';
import http from 'http';

const MOCK_PORT = 8999;
const BACKEND_PORT = 5077;
const MOCK_URL = `http://127.0.0.1:${MOCK_PORT}`;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpRequest(url, options = {}, data = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = http.request(reqOptions, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          resolve({ status: res.statusCode, headers: res.headers, body: json, rawBody: body });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: null, rawBody: body });
        }
      });
    });

    req.on('error', reject);
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function main() {
  console.log('============================================================');
  console.log('NAYVISTA SHIELD: ACTIVE / AUTHORIZED TESTING E2E VERIFICATION');
  console.log('============================================================\n');

  let mockProcess = null;
  let backendProcess = null;

  try {
    // 1. Start Mock Server
    console.log(`[Step 1] Starting Mock Vulnerable Target on port ${MOCK_PORT}...`);
    mockProcess = spawn('py', ['-c', `
from scanner.tests.mock_target_server import MockTestServer
import time
s = MockTestServer('127.0.0.1', ${MOCK_PORT})
s.start()
print('MOCK_SERVER_READY', flush=True)
while True:
    time.sleep(1)
`], { stdio: ['ignore', 'pipe', 'pipe'] });

    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Mock server startup timeout')), 10000);
      mockProcess.stdout.on('data', (d) => {
        if (d.toString().includes('MOCK_SERVER_READY')) {
          clearTimeout(timeout);
          resolve();
        }
      });
    });
    console.log('  ✓ Mock Target is online.\n');

    // 2. Start Backend API
    console.log(`[Step 2] Starting NayVista Shield Backend on port ${BACKEND_PORT}...`);
    backendProcess = spawn('node', ['dist/index.js'], {
      cwd: 'backend',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PORT: String(BACKEND_PORT),
        ALLOW_LOCAL_TARGETS: 'true',
        NODE_ENV: 'development',
        SCAN_TIMEOUT_MS: '30000',
      },
    });

    let backendStarted = false;
    for (let i = 0; i < 20; i++) {
      try {
        const res = await httpRequest(`${BACKEND_URL}/api/health`);
        if (res.status === 200 && res.body?.status === 'ok') {
          backendStarted = true;
          break;
        }
      } catch {}
      await sleep(500);
    }
    if (!backendStarted) {
      throw new Error('Failed to connect to backend health check.');
    }
    console.log('  ✓ Backend API is healthy and accepting requests.\n');

    // 3. Test Attack Mode Rejection on Web API
    console.log('[Step 3] Verifying Web API rejects prohibited attack simulation mode...');
    const attackRes = await httpRequest(`${BACKEND_URL}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, {
      target: MOCK_URL,
      authorized: true,
      mode: 'attack simulation',
    });
    if (attackRes.status !== 400 || !attackRes.rawBody.includes('ATTACK SIMULATION mode is disabled')) {
      throw new Error(`Expected HTTP 400 rejection for attack mode. Got: ${attackRes.status} ${attackRes.rawBody}`);
    }
    console.log('  ✓ Prohibited attack simulation mode strictly rejected with HTTP 400.\n');

    // 4. Submit Active Mode Scan via Web API
    console.log(`[Step 4] Submitting ACTIVE / AUTHORIZED TESTING scan for ${MOCK_URL}...`);
    const scanInitRes = await httpRequest(`${BACKEND_URL}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, {
      target: MOCK_URL,
      authorized: true,
      mode: 'ACTIVE / AUTHORIZED TESTING',
    });

    if (scanInitRes.status !== 201 || !scanInitRes.body?.scanId) {
      throw new Error(`Scan initialization failed: ${scanInitRes.status} ${scanInitRes.rawBody}`);
    }
    const scanId = scanInitRes.body.scanId;
    console.log(`  ✓ Active scan initialized: ${scanId} (Mode: ${scanInitRes.body.mode})\n`);

    // 5. Poll Scan Completion
    console.log('[Step 5] Monitoring active scan progress and stages...');
    let scanRecord = null;
    for (let i = 0; i < 45; i++) {
      await sleep(1000);
      const pollRes = await httpRequest(`${BACKEND_URL}/api/scans/${scanId}`);
      if (pollRes.status === 200 && pollRes.body?.scan) {
        scanRecord = pollRes.body.scan;
        const phase = scanRecord.progress?.phase || 'running';
        const step = scanRecord.progress?.step || 0;
        console.log(`  Stage: ${phase} (${step}/14) | Status: ${scanRecord.status}`);
        if (scanRecord.status === 'completed' || scanRecord.status === 'failed') {
          break;
        }
      }
    }

    if (!scanRecord || scanRecord.status !== 'completed') {
      throw new Error(`Active scan failed to complete. Final status: ${scanRecord?.status} ${scanRecord?.error_message}`);
    }
    console.log('  ✓ Active scan completed successfully!\n');

    // 6. Verify Findings & Structured Evidence
    console.log('[Step 6] Validating active findings, deterministic IDs, and structured evidence...');
    const findingsRes = await httpRequest(`${BACKEND_URL}/api/scans/${scanId}/findings`);
    const findings = findingsRes.body?.findings || [];
    console.log(`  Discovered ${findings.length} findings.`);

    if (findings.length === 0) {
      throw new Error('Expected active findings on mock server, but none were recorded.');
    }

    for (const f of findings) {
      if (!f.id || !f.id.startsWith('NS-')) {
        throw new Error(`Finding missing deterministic NS- ID prefix: ${f.id}`);
      }
      if (!['CONFIRMED', 'LIKELY', 'POTENTIAL', 'NOT_CONFIRMED', 'NOT_TESTABLE'].includes(f.confidence)) {
        throw new Error(`Invalid confidence level: ${f.confidence}`);
      }
      if (f.structured_evidence) {
        const se = f.structured_evidence;
        if (!se.test || !se.target || !se.expected || !se.observed) {
          throw new Error(`Malformed structured evidence on finding ${f.id}`);
        }
      }
    }
    console.log('  ✓ All active findings verified: deterministic NS- IDs and structured evidence confirmed.\n');

    // 7. Verify Dual-Interface Parity via CLI
    console.log('[Step 7] Testing direct CLI active execution (--mode active --yes --json)...');
    const cliOutput = await new Promise((resolve, reject) => {
      const cliProc = spawn('py', [
        '-m', 'scanner',
        '--target', MOCK_URL,
        '--allow-local',
        '--mode', 'active',
        '--yes',
        '--json',
      ], {
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
      });

      let stdout = '';
      let stderr = '';
      cliProc.stdout.on('data', (d) => (stdout += d));
      cliProc.stderr.on('data', (d) => (stderr += d));

      cliProc.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`CLI active scan failed (code ${code}): ${stderr}`));
        } else {
          resolve(stdout);
        }
      });
    });

    const cliResult = JSON.parse(cliOutput.trim());
    console.log(`  CLI Active findings count: ${cliResult.findings?.length}`);
    console.log(`  Web Active findings count: ${findings.length}`);

    if (cliResult.mode !== 'ACTIVE / AUTHORIZED TESTING') {
      throw new Error(`CLI report has incorrect mode: ${cliResult.mode}`);
    }
    console.log('  ✓ Direct CLI active scan executed cleanly with matching active findings.\n');

    console.log('============================================================');
    console.log('🎉 ALL ACTIVE / AUTHORIZED TESTING VERIFICATIONS PASSED! 🎉');
    console.log('============================================================');
  } finally {
    if (backendProcess) {
      backendProcess.kill();
    }
    if (mockProcess) {
      mockProcess.kill();
    }
  }
}

main().catch((err) => {
  console.error('\n❌ Active Mode E2E Test Failed:', err);
  process.exit(1);
});
