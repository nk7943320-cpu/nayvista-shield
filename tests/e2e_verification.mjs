import { spawn } from 'child_process';
import path from 'path';

const BACKEND_PORT = 5055;
process.env.PORT = String(BACKEND_PORT);
process.env.ALLOW_LOCAL_TARGETS = '1';

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runE2E() {
  console.log('=== Starting NayVista Shield End-to-End System Test ===\n');

  // 1. Start Python Mock Vulnerable Server
  console.log('[Step 1] Starting Mock Vulnerable Target on http://127.0.0.1:8999...');
  const mockServerProc = spawn('py', ['-c', `
from scanner.tests.mock_target_server import MockTestServer
import time
s = MockTestServer('127.0.0.1', 8999)
s.start()
print('MOCK_SERVER_READY', flush=True)
while True:
    time.sleep(1)
`], { cwd: process.cwd() });

  await new Promise((resolve) => {
    mockServerProc.stdout.on('data', (d) => {
      if (d.toString().includes('MOCK_SERVER_READY')) resolve();
    });
  });
  console.log('✓ Mock Vulnerable Target is listening.');

  // 2. Start Backend Server
  console.log('[Step 2] Starting NayVista Shield Backend on port ' + BACKEND_PORT + '...');
  const backendProc = spawn('node', ['dist/index.js'], {
    cwd: path.resolve(process.cwd(), 'backend'),
    env: { ...process.env, PORT: String(BACKEND_PORT), ALLOW_LOCAL_TARGETS: '1' }
  });

  backendProc.stdout.on('data', (d) => console.log('  [Backend stdout]:', d.toString().trim()));
  backendProc.stderr.on('data', (d) => console.error('  [Backend stderr]:', d.toString().trim()));

  // Wait for backend to be ready
  let ready = false;
  for (let i = 0; i < 20; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/health`);
      if (res.ok) {
        ready = true;
        break;
      }
    } catch {}
    await wait(500);
  }

  if (!ready) {
    mockServerProc.kill();
    backendProc.kill();
    throw new Error('Backend failed to start');
  }
  console.log('✓ Backend API is healthy.');

  try {
    // 3. Trigger Scan via POST /api/scans
    console.log('[Step 3] Submitting authorized scan request for http://127.0.0.1:8999...');
    const postRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: 'http://127.0.0.1:8999',
        authorized: true
      })
    });

    const postData = await postRes.json();
    console.log('  Response:', postData);
    if (!postData.scanId) throw new Error('No scanId returned');
    const scanId = postData.scanId;

    // 4. Poll /api/scans/:id until completed
    console.log('[Step 4] Monitoring scan progress...');
    let scanCompleted = false;
    let finalScan = null;

    for (let i = 0; i < 40; i++) {
      await wait(1000);
      const pollRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans/${scanId}`);
      const pollData = await pollRes.json();
      const scan = pollData.scan;
      console.log(`  Phase: ${scan.progress?.phase || 'init'} | Step: ${scan.progress?.step || 0}/${scan.progress?.total_steps || 14} | Status: ${scan.status}`);

      if (scan.status === 'completed') {
        scanCompleted = true;
        finalScan = scan;
        break;
      } else if (scan.status === 'failed') {
        throw new Error('Scan failed: ' + scan.error_message);
      }
    }

    if (!scanCompleted) throw new Error('Scan timed out');
    console.log('✓ Web GUI/Backend Scan completed successfully!');
    console.log(`  Mode: ${finalScan.mode}`);
    console.log(`  Score: ${finalScan.security_score}/100 (Grade ${finalScan.grade}) | Risk: ${finalScan.risk_level}`);
    console.log(`  Pages Scanned: ${finalScan.pages_scanned} | Duration: ${finalScan.duration_seconds}s`);

    if (finalScan.mode !== 'DEFENSIVE / SAFE') {
      throw new Error(`Expected mode 'DEFENSIVE / SAFE', got '${finalScan.mode}'`);
    }
    if (!finalScan.dns || !finalScan.dns.ipv4) {
      throw new Error('Expected DNS resolution in scan record');
    }
    console.log(`  DNS: IPv4=${finalScan.dns.ipv4}, IPv6=${finalScan.dns.ipv6 || 'None'}`);
    if (!Array.isArray(finalScan.network_exposure) || finalScan.network_exposure.length === 0) {
      throw new Error('Expected network exposure array in scan record');
    }
    console.log(`  Network Exposure: ${finalScan.network_exposure.length} curated ports probed.`);

    // 5. Test GET /api/scans/:id/findings
    console.log('[Step 5] Fetching and verifying findings...');
    const findingsRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans/${scanId}/findings`);
    const findingsData = await findingsRes.json();
    console.log(`  Total Findings: ${findingsData.findings.length}`);
    if (findingsData.findings.length === 0) throw new Error('Expected findings from mock server, got 0');

    // Check evidence sanitization
    for (const f of findingsData.findings) {
      if (f.evidence && f.evidence.includes('mock_secret_session_token_12345')) {
        throw new Error(`Secret leaked in evidence for finding: ${f.title}`);
      }
    }
    console.log('✓ All findings verified and evidence is strictly sanitized.');

    // 6. Test Reports
    console.log('[Step 6] Verifying JSON & HTML reports...');
    const jsonReportRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans/${scanId}/report?format=json`);
    const jsonReport = await jsonReportRes.json();
    if (!jsonReport.posture || !jsonReport.findings || !jsonReport.network_exposure || !jsonReport.dns) {
      throw new Error('Invalid JSON report structure: missing defensive sections');
    }
    if (jsonReport.mode !== 'DEFENSIVE / SAFE') {
      throw new Error(`Invalid JSON report mode: ${jsonReport.mode}`);
    }

    const htmlReportRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans/${scanId}/report?format=html`);
    const htmlReport = await htmlReportRes.text();
    if (!htmlReport.includes('NAYVISTA SHIELD') || !htmlReport.includes('DEFENSIVE / SAFE') || !htmlReport.includes('Network Exposure')) {
      throw new Error('Invalid HTML report content: missing DEFENSIVE / SAFE or Network Exposure');
    }
    console.log('✓ JSON and printable HTML reports generated cleanly with defensive sections.');

    // 7. Verify Scan History
    console.log('[Step 7] Checking scan history...');
    const historyRes = await fetch(`http://127.0.0.1:${BACKEND_PORT}/api/scans`);
    const historyData = await historyRes.json();
    if (!historyData.scans.some((s) => s.id === scanId)) {
      throw new Error('Scan not found in scan history');
    }
    console.log('✓ Scan record properly persisted in history.');

    // 8. Dual-Interface Parity Verification: CLI vs Web GUI / Backend
    console.log('[Step 8] Testing Dual-Interface Parity (CLI vs Web GUI Backend)...');
    const cliOutput = await new Promise((resolve, reject) => {
      const cliProc = spawn('py', ['-m', 'scanner', 'http://127.0.0.1:8999', '--mode', 'defensive', '--json'], {
        cwd: process.cwd(),
        env: { ...process.env, ALLOW_LOCAL_TARGETS: '1' }
      });
      let out = '';
      let err = '';
      cliProc.stdout.on('data', (d) => { out += d.toString(); });
      cliProc.stderr.on('data', (d) => { err += d.toString(); });
      cliProc.on('close', (code) => {
        if (code !== 0) reject(new Error(`CLI exited with code ${code}: ${err}`));
        else resolve(out);
      });
    });

    const cliResult = JSON.parse(cliOutput.trim());
    console.log(`  CLI Score: ${cliResult.scoring?.score} (Grade ${cliResult.scoring?.grade}) | Findings: ${cliResult.findings?.length}`);
    console.log(`  Web Score: ${finalScan.security_score} (Grade ${finalScan.grade}) | Findings: ${findingsData.findings.length}`);

    if (cliResult.scoring?.score !== finalScan.security_score) {
      throw new Error(`Score parity mismatch: CLI=${cliResult.scoring?.score} vs Web=${finalScan.security_score}`);
    }
    if (cliResult.scoring?.grade !== finalScan.grade) {
      throw new Error(`Grade parity mismatch: CLI=${cliResult.scoring?.grade} vs Web=${finalScan.grade}`);
    }
    if (cliResult.scoring?.risk_level !== finalScan.risk_level) {
      throw new Error(`Risk level parity mismatch: CLI=${cliResult.scoring?.risk_level} vs Web=${finalScan.risk_level}`);
    }
    if (cliResult.findings?.length !== findingsData.findings.length) {
      throw new Error(`Findings count mismatch: CLI=${cliResult.findings?.length} vs Web=${findingsData.findings.length}`);
    }
    if (cliResult.mode !== finalScan.mode) {
      throw new Error(`Mode parity mismatch: CLI=${cliResult.mode} vs Web=${finalScan.mode}`);
    }
    console.log('✓ PERFECT PARITY CONFIRMED: Terminal/CLI and Web GUI share identical engine results!');

    console.log('\n======================================================');
    console.log('🎉 ALL DUAL INTERFACE END-TO-END TESTS PASSED! 🎉');
    console.log('======================================================\n');
  } finally {
    mockServerProc.kill();
    backendProc.kill();
  }
}

runE2E().catch((err) => {
  console.error('\n❌ End-to-End Test Failed:', err);
  process.exit(1);
});
