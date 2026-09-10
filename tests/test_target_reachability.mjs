import { spawn } from 'child_process';
import path from 'path';

async function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function run() {
  console.log('============================================================');
  console.log('NAYVISTA SHIELD: TARGET REACHABILITY & RELIABILITY VERIFICATION');
  console.log('============================================================\n');

  let backendProc = null;
  let mockTarget = null;
  const PORT = 5089;

  try {
    // 1. Verify Python Scanner Engine directly on an Unreachable Target
    console.log('[1/6] Testing ScannerEngine directly on an Unreachable Target (connection refused)...');
    const pythonResult = await new Promise((resolve, reject) => {
      const p = spawn('py', [
        '-m', 'scanner',
        '--target', 'http://127.0.0.1:49876',
        '--allow-local',
        '--json'
      ], {
        cwd: process.cwd(),
        env: { ...process.env, PYTHONPATH: process.cwd() }
      });

      let stdout = '';
      let stderr = '';
      p.stdout.on('data', (d) => { stdout += d.toString(); });
      p.stderr.on('data', (d) => { stderr += d.toString(); });

      p.on('close', (code) => {
        if (code !== 0) {
          return reject(new Error('Scanner exited with non-zero code ' + code + ': ' + stderr));
        }
        try {
          const marker = '===NAYVISTA_RESULT===';
          let jsonStr = stdout;
          if (stdout.includes(marker)) {
            jsonStr = stdout.split(marker)[1].trim();
          } else if (stdout.includes('===SENTINELSCAN_RESULT===')) {
            jsonStr = stdout.split('===SENTINELSCAN_RESULT===')[1].trim();
          }
          const parsed = JSON.parse(jsonStr);
          resolve(parsed);
        } catch (err) {
          reject(new Error('Failed to parse scanner output: ' + err.message + '\nSTDOUT: ' + stdout));
        }
      });
    });

    if (pythonResult.posture !== 'LIMITED') {
      throw new Error('Expected posture LIMITED, got: ' + pythonResult.posture);
    }
    if (pythonResult.scoring?.score !== null && pythonResult.scoring?.score !== undefined) {
      throw new Error('Expected score to be null/None on unreachable target, got: ' + pythonResult.scoring?.score);
    }
    if (pythonResult.assessment_status !== 'COMPLETED_WITH_LIMITATIONS') {
      throw new Error('Expected assessment_status COMPLETED_WITH_LIMITATIONS, got: ' + pythonResult.assessment_status);
    }
    if (!pythonResult.coverage || typeof pythonResult.coverage.coverage_pct !== 'number') {
      throw new Error('Expected valid coverage object, got: ' + JSON.stringify(pythonResult.coverage));
    }
    if (!Array.isArray(pythonResult.limitations) || pythonResult.limitations.length === 0) {
      throw new Error('Expected limitations array to document unreachable stages, got: ' + JSON.stringify(pythonResult.limitations));
    }
    console.log('  ✓ Scanner completed with limitations gracefully:');
    console.log('    - Posture: ' + pythonResult.posture);
    console.log('    - Security Score: ' + (pythonResult.scoring?.score ?? 'N/A'));
    console.log('    - Assessment Status: ' + pythonResult.assessment_status);
    console.log('    - Coverage: ' + pythonResult.coverage.coverage_pct + '% (' + pythonResult.coverage.completed_stages + '/' + pythonResult.coverage.total_stages + ' stages)');
    console.log('    - Limitations recorded: ' + pythonResult.limitations.length);

    // 2. Verify DNS Resolution Failure Prerequisite Logic
    console.log('\n[2/6] Testing DNS Resolution Failure Dependency Awareness...');
    const dnsFailureResult = await new Promise((resolve, reject) => {
      const p = spawn('py', [
        '-m', 'scanner',
        '--target', 'https://nonexistent-nayvista-subdomain-1234567.invalid',
        '--json'
      ], {
        cwd: process.cwd(),
        env: { ...process.env, PYTHONPATH: process.cwd() }
      });

      let stdout = '';
      let stderr = '';
      p.stdout.on('data', (d) => { stdout += d.toString(); });
      p.stderr.on('data', (d) => { stderr += d.toString(); });

      p.on('close', (code) => {
        if (code !== 0) {
          return reject(new Error('DNS scanner test exited with code ' + code + ': ' + stderr));
        }
        try {
          const marker = '===NAYVISTA_RESULT===';
          let jsonStr = stdout;
          if (stdout.includes(marker)) {
            jsonStr = stdout.split(marker)[1].trim();
          } else if (stdout.includes('===SENTINELSCAN_RESULT===')) {
            jsonStr = stdout.split('===SENTINELSCAN_RESULT===')[1].trim();
          }
          resolve(JSON.parse(jsonStr));
        } catch (err) {
          reject(new Error('Failed to parse DNS scanner test output: ' + err.message));
        }
      });
    });

    if (dnsFailureResult.dns?.status !== 'FAILED') {
      throw new Error('Expected DNS status FAILED, got: ' + dnsFailureResult.dns?.status);
    }
    const portStage = dnsFailureResult.stage_status?.['Port Exposure'] || dnsFailureResult.stage_status?.port_exposure;
    if (portStage !== 'SKIPPED') {
      throw new Error('Expected Port Exposure stage to be SKIPPED due to DNS failure, got: ' + portStage);
    }
    if (dnsFailureResult.network_exposure && dnsFailureResult.network_exposure.length > 0) {
      throw new Error('Expected zero port exposures when DNS fails, got: ' + JSON.stringify(dnsFailureResult.network_exposure));
    }
    const scopeStage = dnsFailureResult.stage_status?.['Scope Validation'] || dnsFailureResult.stage_status?.scope_validation;
    console.log('  ✓ DNS failure handled cleanly as dependency prerequisite:');
    console.log('    - DNS Status: ' + dnsFailureResult.dns?.status);
    console.log('    - Scope Validation: ' + scopeStage);
    console.log('    - Port Exposure: ' + portStage + ' (no TCP probes invented)');
    console.log('    - Security Score: ' + (dnsFailureResult.scoring?.score ?? 'N/A'));

    // 3. Start Backend & Verify Full End-to-End Flow for Unreachable Target
    console.log('\n[3/6] Starting Backend on port ' + PORT + ' with local targets allowed...');
    backendProc = spawn('node', ['dist/index.js'], {
      cwd: path.resolve(process.cwd(), 'backend'),
      env: { ...process.env, PORT: String(PORT), ALLOW_LOCAL_TARGETS: '1' }
    });

    let backendReady = false;
    for (let i = 0; i < 25; i++) {
      try {
        const res = await fetch('http://127.0.0.1:' + PORT + '/api/health');
        if (res.ok) { backendReady = true; break; }
      } catch {}
      await wait(400);
    }
    if (!backendReady) throw new Error('Backend failed to start on port ' + PORT);
    console.log('  ✓ Backend online and healthy.');

    console.log('\n[4/6] Initializing scan for unreachable target via Web Backend API...');
    const scanInitRes = await fetch('http://127.0.0.1:' + PORT + '/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://127.0.0.1:49876', authorized: true })
    });
    const scanInitData = await scanInitRes.json();
    if (!scanInitRes.ok || !scanInitData.scanId) {
      throw new Error('Failed to initialize scan: ' + JSON.stringify(scanInitData));
    }
    const scanId = scanInitData.scanId;
    console.log('  ✓ Scan initialized: ' + scanId);

    // Poll until completion
    let completedScan = null;
    for (let i = 0; i < 40; i++) {
      await wait(1000);
      const res = await fetch('http://127.0.0.1:' + PORT + '/api/scans/' + scanId);
      if (res.ok) {
        const data = await res.json();
        if (data.scan?.status === 'completed' || data.scan?.status === 'failed') {
          completedScan = data.scan;
          break;
        }
      }
    }

    if (!completedScan) {
      throw new Error('Scan did not complete within expected timeout window');
    }
    if (completedScan.status !== 'completed') {
      throw new Error('Expected scan status completed, but got: ' + completedScan.status + ' (error: ' + completedScan.error_message + ')');
    }
    if (completedScan.posture !== 'LIMITED') {
      throw new Error('Expected scan posture LIMITED, got: ' + completedScan.posture);
    }
    if (completedScan.security_score !== null) {
      throw new Error('Expected security_score to be null, got: ' + completedScan.security_score);
    }
    if (!completedScan.is_limited) {
      throw new Error('Expected is_limited to be true');
    }
    console.log('  ✓ End-to-end unreachable scan completed with partial assessment:');
    console.log('    - Status: ' + completedScan.status);
    console.log('    - Posture: ' + completedScan.posture);
    console.log('    - Security Score: ' + (completedScan.security_score ?? 'null (N/A)'));
    console.log('    - Assessment Status: ' + completedScan.assessment_status);
    console.log('    - Coverage: ' + completedScan.coverage?.coverage_pct + '%');

    // 5. Verify Report Generation for Limited Scan
    console.log('\n[5/6] Verifying JSON and HTML reports for Limited Scan...');
    const reportRes = await fetch('http://127.0.0.1:' + PORT + '/api/scans/' + scanId + '/report?format=json');
    const reportData = await reportRes.json();
    if (reportData.posture !== 'LIMITED' || reportData.executive_summary?.security_score !== null) {
      throw new Error('JSON report does not reflect limited assessment posture');
    }

    const htmlRes = await fetch('http://127.0.0.1:' + PORT + '/api/scans/' + scanId + '/report?format=html');
    const htmlContent = await htmlRes.text();
    if (!htmlContent.includes('[ ASSESSMENT LIMITED ]')) {
      throw new Error('HTML report missing [ ASSESSMENT LIMITED ] banner');
    }
    if (!htmlContent.includes('COMPLETED WITH LIMITATIONS')) {
      throw new Error('HTML report missing COMPLETED WITH LIMITATIONS status');
    }
    console.log('  ✓ Reports reflect [ ASSESSMENT LIMITED ], score N/A, and coverage breakdown.');

    // 6. Verify Failure Domain Separation
    console.log('\n[6/6] Verifying Failure Domain Classification...');
    // A. Attack simulation rejection
    const attackSimRes = await fetch('http://127.0.0.1:' + PORT + '/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://example.com', authorized: true, mode: 'ATTACK SIMULATION' })
    });
    if (attackSimRes.status !== 400) {
      throw new Error('Attack simulation was not rejected');
    }

    // B. SSRF protection
    const ssrfRes = await fetch('http://127.0.0.1:' + PORT + '/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://169.254.169.254/latest/meta-data', authorized: true })
    });
    const ssrfData = await ssrfRes.json();
    if (ssrfRes.status !== 400 || !ssrfData.error?.includes('cloud metadata')) {
      throw new Error('SSRF protection failed: ' + JSON.stringify(ssrfData));
    }
    console.log('  ✓ SSRF & Cloud Metadata protection strictly active.');
    console.log('  ✓ Attack simulation mode strictly disabled.');

    console.log('\n============================================================');
    console.log('ALL TARGET REACHABILITY & RELIABILITY TESTS PASSED (6/6)');
    console.log('============================================================');
  } finally {
    if (mockTarget) {
      try { mockTarget.kill(); } catch {}
    }
    if (backendProc) {
      try { backendProc.kill(); } catch {}
    }
  }
}

run().catch((err) => {
  console.error('\n❌ Test failed with error:', err);
  process.exit(1);
});
