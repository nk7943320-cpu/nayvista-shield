import { spawn } from 'child_process';
import path from 'path';

async function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function run() {
  console.log('=== Running Comprehensive Web GUI Initialization Resilience Verification ===\n');

  // 1. Start Python Mock Vulnerable Target
  console.log('[1/7] Starting Mock Vulnerable Target...');
  const mockTarget = spawn('py', ['-c', `
from scanner.tests.mock_target_server import MockTestServer
import time
s = MockTestServer('127.0.0.1', 8999)
s.start()
print('MOCK_TARGET_READY', flush=True)
while True:
    time.sleep(1)
`], { cwd: process.cwd() });

  await new Promise((resolve) => {
    mockTarget.stdout.on('data', (d) => {
      if (d.toString().includes('MOCK_TARGET_READY')) resolve();
    });
  });
  console.log('  ✓ Mock Target online on http://127.0.0.1:8999');

  // 2. Start Backend on Port 5088
  const PORT = 5088;
  console.log(`[2/7] Starting Backend on port ${PORT}...`);
  const backendProc = spawn('node', ['dist/index.js'], {
    cwd: path.resolve(process.cwd(), 'backend'),
    env: { ...process.env, PORT: String(PORT), ALLOW_LOCAL_TARGETS: '1' }
  });

  let ready = false;
  for (let i = 0; i < 20; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/api/health`);
      if (res.ok) { ready = true; break; }
    } catch {}
    await wait(400);
  }
  if (!ready) throw new Error('Backend failed to start');
  console.log('  ✓ Backend online and healthy.');

  try {
    // 3. Test Successful Assessment Initialization
    console.log('[3/7] Testing Successful Assessment Initialization Contract...');
    const initRes = await fetch(`http://127.0.0.1:${PORT}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://127.0.0.1:8999', authorized: true })
    });
    const initData = await initRes.json();
    if (!initRes.ok || !initData.scanId) {
      throw new Error('Initialization failed: ' + JSON.stringify(initData));
    }
    console.log(`  ✓ Scan initialized successfully with valid scanId: ${initData.scanId}`);

    // 4. Test Missing Authorization Rejection
    console.log('[4/7] Testing Missing Authorization Rejection...');
    const unauthRes = await fetch(`http://127.0.0.1:${PORT}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://127.0.0.1:8999', authorized: false })
    });
    const unauthData = await unauthRes.json();
    if (unauthRes.status !== 400 || !unauthData.error?.includes('explicitly authorized')) {
      throw new Error('Unauth check failed');
    }
    console.log('  ✓ Missing authorization rejected with HTTP 400 JSON.');

    // 5. Test Invalid Target URL Rejection
    console.log('[5/7] Testing Invalid Target URL Rejection...');
    const invalidUrlRes = await fetch(`http://127.0.0.1:${PORT}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'not-a-valid-url', authorized: true })
    });
    const invalidUrlData = await invalidUrlRes.json();
    if (invalidUrlRes.status !== 400 || !invalidUrlData.error) {
      throw new Error('Invalid URL check failed');
    }
    console.log('  ✓ Invalid URL rejected with HTTP 400 JSON.');

    // 6. Test Malformed JSON Body Handling
    console.log('[6/7] Testing Malformed Request Body Handling...');
    const malformedRes = await fetch(`http://127.0.0.1:${PORT}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken: payload'
    });
    const malformedData = await malformedRes.json();
    if (malformedRes.status !== 400 || malformedData.code !== 'INVALID_JSON') {
      throw new Error('Malformed body handling failed');
    }
    console.log('  ✓ Malformed JSON rejected with HTTP 400 INVALID_JSON.');

    // 7. Test Global 404 Route
    console.log('[7/7] Testing Global 404 Route JSON Contract...');
    const notFoundRes = await fetch(`http://127.0.0.1:${PORT}/api/non-existent`);
    const notFoundData = await notFoundRes.json();
    if (notFoundRes.status !== 404 || notFoundData.code !== 'NOT_FOUND') {
      throw new Error('404 handling failed');
    }
    console.log('  ✓ Route not found returns HTTP 404 NOT_FOUND JSON.');

    console.log('\n======================================================');
    console.log('🎉 ALL INTEGRATION RESILIENCE CHECKS PASSED! 🎉');
    console.log('======================================================\n');
  } finally {
    backendProc.kill();
    mockTarget.kill();
  }
}

run().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
