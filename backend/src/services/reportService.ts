import { ScanRecord, Finding, Severity } from '../types/index.js';
import { sanitizeLogString } from '../utils/logger.js';

function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export class ReportService {
  /**
   * Sanitizes all fields in findings and text before report generation.
   * Unconditionally redacts tokens, cookies, auth headers, passwords, and private keys.
   */
  sanitizeEvidence(text: string): string {
    return sanitizeLogString(text);
  }

  generateJsonReport(scan: ScanRecord, rawFindings: Finding[]): any {
    const findings = rawFindings.map(f => ({
      ...f,
      evidence: this.sanitizeEvidence(f.evidence || ''),
      description: this.sanitizeEvidence(f.description || ''),
    }));

    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;
    const mediums = findings.filter(f => f.severity === 'MEDIUM').length;
    const lows = findings.filter(f => f.severity === 'LOW').length;
    const infos = findings.filter(f => f.severity === 'INFO').length;

    const posture = scan.posture || 'ASSESSED';

    // Ranked remediation priority (Severity weights: Critical=5, High=4, Medium=3, Low=2, Info=1)
    const severityWeight: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const rankedRemediations = [...findings]
      .sort((a, b) => {
        const diff = (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
        if (diff !== 0) return diff;
        return (b.affected_urls?.length || 1) - (a.affected_urls?.length || 1);
      })
      .map((f, i) => ({
        priority: i + 1,
        finding_id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        owasp: f.owasp,
        cwe: f.cwe || 'CWE-693',
        affected_component: f.affected_component || f.scanner,
        action: f.remediation,
      }));

    return {
      report_type: 'NayVista Shield Security Assessment Report',
      product: 'NayVista Shield',
      organization: 'NayVista Technologies',
      tagline: 'AI-Assisted Web Security Assessment',
      version: '1.0.0',
      generated_at: new Date().toISOString(),
      posture,
      assessment_status: scan.assessment_status || (posture === 'LIMITED' ? 'COMPLETED_WITH_LIMITATIONS' : 'COMPLETED'),
      coverage: scan.coverage || null,
      stage_status: scan.stage_status || null,
      limitations: scan.limitations || [],
      is_limited: scan.is_limited || posture === 'LIMITED',
      mode: scan.mode || 'DEFENSIVE / SAFE',
      resolved_ip: scan.resolved_ip || 'N/A',
      dns: scan.dns,
      network_exposure: scan.network_exposure || [],
      scan_id: scan.id,
      target_url: scan.target_url,
      metadata: {
        scan_id: scan.id,
        tenant_id: scan.tenant_id || 'default',
        target_url: scan.target_url,
        target_hostname: scan.target_hostname,
        target_port: scan.target_port,
        target_scheme: scan.target_scheme,
        mode: scan.mode || 'DEFENSIVE / SAFE',
        resolved_ip: scan.resolved_ip || 'N/A',
        dns: scan.dns,
        authorized: scan.authorized,
        started_at: scan.started_at,
        completed_at: scan.completed_at,
        duration_seconds: scan.duration_seconds,
        pages_scanned: scan.pages_scanned,
        posture,
        assessment_status: scan.assessment_status || (posture === 'LIMITED' ? 'COMPLETED_WITH_LIMITATIONS' : 'COMPLETED'),
        coverage: scan.coverage || null,
        stage_status: scan.stage_status || null,
        limitations: scan.limitations || [],
        is_limited: scan.is_limited || posture === 'LIMITED',
        status: scan.status,
      },
      executive_summary: {
        security_score: scan.security_score,
        score_display: scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : 'N/A',
        grade: scan.grade || 'N/A',
        risk_level: scan.risk_level || (posture === 'LIMITED' ? 'LIMITED' : 'LOW'),
        assessment_posture: posture,
        assessment_status: scan.assessment_status || (posture === 'LIMITED' ? 'COMPLETED_WITH_LIMITATIONS' : 'COMPLETED'),
        coverage: scan.coverage || null,
        completeness: posture === 'LIMITED' ? 'Completed with Limitations (Target Connectivity/Reachability)' : (posture === 'RESTRICTED' ? 'Restricted by Target WAF' : (posture === 'DEGRADED' ? 'Degraded by Server Errors' : 'Comprehensive')),
        total_findings: findings.length,
      },
      risk_overview: {
        critical: criticals,
        high: highs,
        medium: mediums,
        low: lows,
        info: infos,
      },
      key_observations: findings.slice(0, 5).map(f => ({
        title: f.title,
        severity: f.severity,
        summary: f.description,
      })),
      attack_surface: scan.inventory || {
        total_pages: scan.pages_scanned,
        endpoints: [],
        parameters: [],
        forms_count: 0,
        forms: [],
        api_endpoints: [],
      },
      technology_observations: scan.technologies || {
        web_servers: [],
        backend: [],
        cms: [],
        frontend: [],
        libraries: [],
      },
      assessment_limitations: this.deriveLimitations(posture, scan.status, scan.pages_scanned, scan.limitations),
      remediation_priorities: rankedRemediations,
      findings,
    };
  }

  private deriveLimitations(posture: string, status: string, pagesScanned: number, explicitLimitations?: any[]): string[] {
    if (explicitLimitations && explicitLimitations.length > 0) {
      return explicitLimitations.map(l => typeof l === 'string' ? l : (l.description || l.code || 'Assessment limitation encountered.'));
    }
    const limitations: string[] = [];
    if (posture === 'LIMITED') {
      limitations.push('Assessment was completed with limitations due to target reachability or connectivity constraints. Security score is N/A due to insufficient evidence.');
    }
    if (posture === 'RESTRICTED') {
      limitations.push('Assessment was restricted by the target Web Application Firewall (WAF) or edge bot protection (HTTP 403 / 429). Full subsurface enumeration was constrained.');
    }
    if (posture === 'DEGRADED') {
      limitations.push('Target returned unhandled server errors (HTTP 5xx) or TLS verification failures. Analysis was limited to non-destructive inspection.');
    }
    if (status === 'timeout') {
      limitations.push('Assessment hit the watchdog execution timeout and was safely interrupted before exhaustive completion.');
    }
    if (pagesScanned <= 1) {
      limitations.push('Crawl depth was limited to the initial landing page.');
    }
    if (limitations.length === 0) {
      limitations.push('No operational restrictions encountered. Defensive audit executed within authorized same-origin boundaries.');
    }
    return limitations;
  }

  generateHtmlReport(scan: ScanRecord, rawFindings: Finding[]): string {
    const findings = rawFindings.map(f => ({
      ...f,
      evidence: this.sanitizeEvidence(f.evidence || ''),
      description: this.sanitizeEvidence(f.description || ''),
    }));

    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;
    const mediums = findings.filter(f => f.severity === 'MEDIUM').length;
    const lows = findings.filter(f => f.severity === 'LOW').length;
    const infos = findings.filter(f => f.severity === 'INFO').length;

    const posture = scan.posture || 'ASSESSED';
    const limitations = this.deriveLimitations(posture, scan.status, scan.pages_scanned);

    // Remediation Ranking
    const severityWeight: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const rankedFindings = [...findings].sort((a, b) => {
      const diff = (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
      if (diff !== 0) return diff;
      return (b.affected_urls?.length || 1) - (a.affected_urls?.length || 1);
    });

    const sevBadge = (sev: string) => {
      switch (sev) {
        case 'CRITICAL': return '<span class="badge badge-critical">CRITICAL</span>';
        case 'HIGH': return '<span class="badge badge-high">HIGH</span>';
        case 'MEDIUM': return '<span class="badge badge-medium">MEDIUM</span>';
        case 'LOW': return '<span class="badge badge-low">LOW</span>';
        default: return '<span class="badge badge-info">INFO</span>';
      }
    };

    // Build Detailed Findings Rows
    const findingsHtml = findings.map((f, idx) => `
      <div class="finding-card">
        <div class="finding-header">
          <div class="finding-title-row">
            ${sevBadge(f.severity)}
            <span class="finding-idx">#${String(idx + 1).padStart(2, '0')}</span>
            <span class="finding-title">${escapeHtml(f.title)}</span>
          </div>
          <div class="finding-meta">
            <span class="meta-tag">CONFIDENCE: <strong>${escapeHtml(f.confidence)}</strong></span>
            <span class="meta-tag">OWASP: <strong>${escapeHtml(f.owasp || 'A05:2021')}</strong></span>
            <span class="meta-tag">CWE: <strong>${escapeHtml(f.cwe || 'CWE-693')}</strong></span>
            <span class="meta-tag">STATUS: <strong>${escapeHtml(f.status || 'OPEN')}</strong></span>
          </div>
        </div>

        <div class="finding-body">
          <div class="prop-group">
            <div class="prop-label">TARGET / COMPONENT:</div>
            <div class="prop-value mono-val">${escapeHtml(f.url)} ${f.affected_component ? `[${escapeHtml(f.affected_component)}]` : ''}</div>
          </div>

          <div class="prop-group">
            <div class="prop-label">TECHNICAL DESCRIPTION:</div>
            <div class="prop-value">${escapeHtml(f.description)}</div>
          </div>

          <div class="prop-group">
            <div class="prop-label">OBSERVED EVIDENCE (SANITIZED):</div>
            <pre class="evidence-box">${escapeHtml(f.evidence || 'No specific telemetry captured.')}</pre>
          </div>

          <div class="prop-group">
            <div class="prop-label">POTENTIAL IMPACT:</div>
            <div class="prop-value impact-text">${escapeHtml(f.impact)}</div>
          </div>

          <div class="prop-group">
            <div class="prop-label">RECOMMENDED REMEDIATION:</div>
            <div class="prop-value remediation-box">${escapeHtml(f.remediation)}</div>
          </div>

          ${(f.references && f.references.length > 0) ? `
          <div class="prop-group">
            <div class="prop-label">STANDARDS & REFERENCES:</div>
            <ul class="ref-list">
              ${f.references.map(r => `<li><a href="${escapeHtml(r)}" target="_blank" rel="noreferrer">${escapeHtml(r)}</a></li>`).join('')}
            </ul>
          </div>` : ''}
        </div>
      </div>
    `).join('');

    // Tech stack
    const rawTech = scan.technologies || ({} as Record<string, any>);
    const tech: Record<string, string[]> = {
      web_servers: Array.isArray(rawTech.web_servers) ? rawTech.web_servers : [],
      backend: Array.isArray(rawTech.backend) ? rawTech.backend : [],
      cms: Array.isArray(rawTech.cms) ? rawTech.cms : [],
      frontend: Array.isArray(rawTech.frontend) ? rawTech.frontend : [],
      libraries: Array.isArray(rawTech.libraries) ? rawTech.libraries : [],
    };
    const allTech: string[] = [
      ...tech.web_servers.map((t: string) => `Server: ${t}`),
      ...tech.backend.map((t: string) => `Backend: ${t}`),
      ...tech.cms.map((t: string) => `CMS: ${t}`),
      ...tech.frontend.map((t: string) => `Frontend: ${t}`),
      ...tech.libraries.map((t: string) => `Library: ${t}`),
    ];

    // Attack Surface stats
    const rawInv = scan.inventory || ({} as Record<string, any>);
    const inv = {
      total_pages: typeof rawInv.total_pages === 'number' ? rawInv.total_pages : (scan.pages_scanned || 0),
      endpoints: (Array.isArray(rawInv.endpoints) ? rawInv.endpoints : []) as string[],
      forms_count: typeof rawInv.forms_count === 'number' ? rawInv.forms_count : (Array.isArray(rawInv.forms) ? rawInv.forms.length : 0),
      forms: Array.isArray(rawInv.forms) ? rawInv.forms : [],
      parameters: (Array.isArray(rawInv.parameters) ? rawInv.parameters : []) as string[],
      api_endpoints: (Array.isArray(rawInv.api_endpoints) ? rawInv.api_endpoints : []) as string[],
    };

    // Network Port Exposure
    const exposureList = scan.network_exposure || [];
    const exposureTableHtml = exposureList.length > 0
      ? `<table>
          <thead>
            <tr>
              <th>PORT</th>
              <th>SERVICE</th>
              <th>STATE</th>
              <th>EXPOSURE</th>
              <th>CONTEXTUAL RISK</th>
            </tr>
          </thead>
          <tbody>
            ${exposureList.map(exp => `
              <tr>
                <td style="font-family: monospace; font-weight: bold;">TCP/${exp.port}</td>
                <td>${escapeHtml(exp.service)}</td>
                <td style="color: ${exp.state === 'OPEN' ? 'var(--low)' : 'var(--text-muted)'}; font-weight: bold;">${escapeHtml(exp.state)}</td>
                <td>${escapeHtml(exp.exposure || '-')}</td>
                <td style="color: ${exp.risk === 'HIGH' ? 'var(--critical)' : (exp.risk === 'REVIEW' ? 'var(--high)' : (exp.risk === 'EXPECTED' ? 'var(--low)' : 'var(--text-muted)'))}; font-weight: bold;">${escapeHtml(exp.risk || '-')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>`
      : `<p style="color: var(--text-muted); font-size: 11px;">No curated network port exposure records found.</p>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NayVista Shield Security Assessment Report - ${escapeHtml(scan.target_hostname)}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 14mm 12mm;
    }
    :root {
      --bg: #0A0A0A;
      --panel: #111111;
      --panel-border: #2B2615;
      --primary: #FFD400;
      --primary-dim: #997F00;
      --text: #F5E8BA;
      --text-muted: #9E9373;
      --text-bright: #FFFCEB;
      --border: #222222;
      --critical: #FF4444;
      --high: #FF9900;
      --medium: #FFD400;
      --low: #84CC16;
      --info: #8899A6;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 11.5px;
      line-height: 1.5;
      padding: 24px;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }

    .container { max-width: 960px; margin: 0 auto; }

    /* Header */
    .report-header {
      border: 2px solid var(--primary);
      background: var(--panel);
      padding: 20px 24px;
      margin-bottom: 24px;
      position: relative;
    }
    .header-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--panel-border);
      padding-bottom: 12px;
      margin-bottom: 14px;
    }
    .brand-title {
      font-size: 18px;
      font-weight: 900;
      letter-spacing: 1px;
      color: var(--primary);
    }
    .brand-org {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1.5px;
    }
    .report-type-badge {
      background: #2B2300;
      border: 1px solid var(--primary);
      color: var(--primary);
      padding: 4px 8px;
      font-weight: bold;
      font-size: 10px;
      text-transform: uppercase;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 8px 16px;
      font-size: 11px;
    }
    .meta-item strong { color: var(--text-bright); }

    /* Sections */
    .section {
      background: var(--panel);
      border: 1px solid var(--panel-border);
      padding: 18px 22px;
      margin-bottom: 20px;
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .section-title {
      font-size: 13px;
      font-weight: bold;
      text-transform: uppercase;
      color: var(--primary);
      border-bottom: 1px solid var(--panel-border);
      padding-bottom: 6px;
      margin-bottom: 14px;
      letter-spacing: 1px;
      display: flex;
      justify-content: space-between;
    }

    /* Executive Summary */
    .exec-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 12px;
    }
    .exec-card {
      border: 1px solid var(--panel-border);
      background: #0D0D0D;
      padding: 12px;
      text-align: center;
    }
    .exec-label { font-size: 9px; text-transform: uppercase; color: var(--text-muted); }
    .exec-val { font-size: 24px; font-weight: 900; color: var(--text-bright); margin-top: 4px; }
    .score-accent { color: var(--primary); }

    /* Risk Overview */
    .risk-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 8px;
    }
    .risk-box {
      padding: 8px;
      text-align: center;
      border: 1px solid var(--border);
      background: #080808;
    }
    .risk-box.critical { border-color: #661111; background: #260A0A; color: #FFAAAA; }
    .risk-box.high { border-color: #663300; background: #261400; color: #FFCC88; }
    .risk-box.medium { border-color: #665500; background: #262000; color: #FFEE88; }
    .risk-box.low { border-color: #224400; background: #101F00; color: #CCFF88; }
    .risk-box.info { border-color: #333333; background: #141414; color: #CCD5DD; }
    .risk-num { font-size: 18px; font-weight: bold; }
    .risk-name { font-size: 9px; text-transform: uppercase; }

    /* Findings */
    .finding-card {
      border: 1px solid var(--panel-border);
      background: #0E0E0E;
      margin-bottom: 14px;
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .finding-header {
      background: #16140B;
      padding: 10px 14px;
      border-bottom: 1px solid var(--panel-border);
    }
    .finding-title-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: bold;
      color: var(--text-bright);
    }
    .finding-idx { color: var(--text-muted); font-size: 10px; }
    .finding-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 6px;
      font-size: 10px;
      color: var(--text-muted);
    }
    .finding-meta strong { color: var(--text-bright); }
    .finding-body { padding: 12px 14px; font-size: 11px; }

    .prop-group { margin-bottom: 10px; }
    .prop-label { font-size: 9px; text-transform: uppercase; color: var(--primary-dim); font-weight: bold; margin-bottom: 2px; }
    .prop-value { color: var(--text); }
    .mono-val { color: var(--primary); word-break: break-all; }
    .impact-text { color: #FFAA88; }
    .remediation-box {
      background: #141207;
      border-left: 3px solid var(--primary);
      padding: 6px 10px;
      color: var(--text-bright);
    }
    .evidence-box {
      background: #050505;
      border: 1px solid #222;
      padding: 8px;
      font-family: inherit;
      font-size: 10px;
      color: #94E2D5;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .ref-list { list-style: square inside; margin-top: 4px; font-size: 10px; color: var(--text-muted); }
    .ref-list a { color: var(--primary); text-decoration: none; word-break: break-all; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 10.5px; }
    th, td { border: 1px solid var(--panel-border); padding: 6px 10px; text-align: left; }
    th { background: #16140B; color: var(--primary); font-size: 9.5px; text-transform: uppercase; }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 2px 6px;
      font-size: 9px;
      font-weight: bold;
      text-transform: uppercase;
      border-radius: 2px;
    }
    .badge-critical { background: #3B0B0B; color: #FF7777; border: 1px solid #771111; }
    .badge-high { background: #3B1B00; color: #FFAA44; border: 1px solid #773300; }
    .badge-medium { background: #332B00; color: #FFDD44; border: 1px solid #776600; }
    .badge-low { background: #1B3304; color: #99EE44; border: 1px solid #336608; }
    .badge-info { background: #1A1D20; color: #AAB8C2; border: 1px solid #3A444C; }

    /* Print Specific Formatting */
    @media print {
      body {
        background: #FFFFFF !important;
        color: #111111 !important;
        padding: 0 !important;
        font-size: 10px !important;
      }
      .report-header, .section, .finding-card, .exec-card, .risk-box {
        background: #FFFFFF !important;
        color: #111111 !important;
        border: 1px solid #CCCCCC !important;
        page-break-inside: avoid !important;
        break-inside: avoid !important;
      }
      .brand-title, .section-title, .prop-label, th {
        color: #886600 !important;
      }
      .finding-header, th {
        background: #F4F4F4 !important;
        border-bottom: 1px solid #CCCCCC !important;
      }
      .prop-value, .finding-title-row, .meta-item strong {
        color: #000000 !important;
      }
      .remediation-box {
        background: #F9F9F5 !important;
        border-left: 3px solid #886600 !important;
        color: #111111 !important;
      }
      .evidence-box {
        background: #F5F5F5 !important;
        color: #222222 !important;
        border: 1px solid #DDDDDD !important;
      }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="report-header">
      <div class="header-top">
        <div>
          <div class="brand-title">NAYVISTA SHIELD // SECURITY AUDIT REPORT</div>
          <div class="brand-org">NayVista Technologies &bull; AI-Assisted Web Security Assessment</div>
        </div>
        <div class="report-type-badge">${escapeHtml(posture)} POSTURE</div>
      </div>
      <div class="meta-grid">
        <div class="meta-item">TARGET: <strong>${escapeHtml(scan.target_hostname)}</strong> (${escapeHtml(scan.target_url)})</div>
        <div class="meta-item">ASSESSMENT MODE: <strong>${escapeHtml(scan.mode || 'DEFENSIVE / SAFE')}</strong></div>
        <div class="meta-item">RESOLVED IP: <strong>${escapeHtml(scan.resolved_ip || 'N/A')}</strong></div>
        <div class="meta-item">ASSESSMENT DATE: <strong>${new Date(scan.started_at).toISOString().replace('T', ' ').slice(0, 19)} UTC</strong></div>
        <div class="meta-item">SCAN DURATION: <strong>${scan.duration_seconds || 0}s</strong></div>
        <div class="meta-item">SCAN ID: <strong>${escapeHtml(scan.id)}</strong></div>
        <div class="meta-item">PAGES AUDITED: <strong>${scan.pages_scanned} discovered pages</strong></div>
        <div class="meta-item">ENGINE VERSION: <strong>v1.0.0 (Strict Defensive Scope)</strong></div>
      </div>
    </header>

    ${(scan.is_limited || posture === 'LIMITED' || (scan.limitations && scan.limitations.length > 0)) ? `
    <div style="border: 1px solid #FFD400; background: #181507; padding: 14px 18px; margin-bottom: 20px; border-radius: 4px;">
      <div style="color: #FFD400; font-weight: bold; font-size: 13px; margin-bottom: 6px; letter-spacing: 0.5px;">[ ASSESSMENT LIMITED ]</div>
      <div style="color: #FFFCEB; font-size: 11px; margin-bottom: 4px;"><strong>STATUS:</strong> COMPLETED WITH LIMITATIONS</div>
      <div style="color: #9E9373; font-size: 11px; margin-bottom: 4px;"><strong>TARGET:</strong> ${escapeHtml(scan.target_url)}</div>
      <div style="color: #9E9373; font-size: 11px; margin-bottom: 10px;"><strong>REASON:</strong> ${escapeHtml(scan.limitations?.[0]?.description || 'Target could not be reached (connection timed out or host unreachable).')}</div>
      <div style="display: flex; gap: 24px; margin-bottom: 10px; font-size: 11px;">
        <div><strong>SECURITY SCORE:</strong> <span style="color: #FFD400; font-weight: bold;">N/A</span> (Insufficient evidence)</div>
        <div><strong>ASSESSMENT COVERAGE:</strong> <span style="color: #FFD400; font-weight: bold;">${scan.coverage?.coverage_pct ?? 0}%</span> (${scan.coverage?.completed_stages ?? 0} / ${scan.coverage?.total_stages ?? 14} stages completed)</div>
      </div>
      ${(scan.limitations && scan.limitations.length > 0) ? `
      <div style="margin-top: 8px;">
        <div style="font-size: 10px; text-transform: uppercase; color: #FFD400; font-weight: bold; margin-bottom: 4px;">Encountered Limitations:</div>
        <ul style="padding-left: 18px; font-size: 11px; color: #F5E8BA;">
          ${scan.limitations.map(l => `<li><strong>${escapeHtml(l.stage)}:</strong> ${escapeHtml(l.description || l.reason || l.code || '')}</li>`).join('')}
        </ul>
      </div>` : ''}
      <div style="font-size: 10px; color: #888888; font-style: italic; margin-top: 10px;">Note: Assessment limitations do not by themselves indicate a security vulnerability. Probing was halted or skipped safely to prevent false conclusions.</div>
    </div>` : ''}

    <!-- 1. Executive Summary -->
    <section class="section">
      <div class="section-title">01 // EXECUTIVE ASSESSMENT SUMMARY</div>
      <div class="exec-grid">
        <div class="exec-card">
          <div class="exec-label">SECURITY SCORE</div>
          <div class="exec-val score-accent">${scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}<span style="font-size: 14px;">/100</span>` : 'N/A'}</div>
        </div>
        <div class="exec-card">
          <div class="exec-label">CALIBRATED GRADE</div>
          <div class="exec-val">${escapeHtml(scan.grade || 'N/A')}</div>
        </div>
        <div class="exec-card">
          <div class="exec-label">RISK PROFILE</div>
          <div class="exec-val">${escapeHtml(scan.risk_level || (posture === 'LIMITED' ? 'LIMITED' : 'LOW'))}</div>
        </div>
        <div class="exec-card">
          <div class="exec-label">TOTAL FINDINGS</div>
          <div class="exec-val">${findings.length}</div>
        </div>
      </div>
      <p style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
        Assessment posture calibrated as <strong>${escapeHtml(posture)}</strong>.
        ${posture === 'LIMITED' ? 'Assessment completed with limitations due to target reachability or connectivity constraints. Security score is N/A due to insufficient evidence.' : ''}
        ${posture === 'RESTRICTED' ? 'Origin returned bot protection/rate limiting controls (HTTP 403/429); score capped accordingly.' : ''}
        ${posture === 'DEGRADED' ? 'Origin encountered unhandled server conditions (HTTP 5xx) or TLS verification errors.' : ''}
        ${posture === 'ASSESSED' ? 'Same-origin targets reached and assessed successfully.' : ''}
      </p>
    </section>

    <!-- 2. Risk Overview -->
    <section class="section">
      <div class="section-title">02 // RISK SEVERITY DISTRIBUTION</div>
      <div class="risk-grid">
        <div class="risk-box critical"><div class="risk-num">${criticals}</div><div class="risk-name">CRITICAL</div></div>
        <div class="risk-box high"><div class="risk-num">${highs}</div><div class="risk-name">HIGH</div></div>
        <div class="risk-box medium"><div class="risk-num">${mediums}</div><div class="risk-name">MEDIUM</div></div>
        <div class="risk-box low"><div class="risk-num">${lows}</div><div class="risk-name">LOW</div></div>
        <div class="risk-box info"><div class="risk-num">${infos}</div><div class="risk-name">INFO</div></div>
      </div>
    </section>

    <!-- 3. Host & Network Exposure -->
    <section class="section">
      <div class="section-title">03 // HOST &amp; NETWORK SERVICE EXPOSURE</div>
      <div class="meta-grid" style="margin-bottom: 12px;">
        <div class="meta-item">HOSTNAME: <strong>${escapeHtml(scan.target_hostname)}</strong></div>
        <div class="meta-item">RESOLVED IPV4: <strong>${escapeHtml(scan.dns?.ipv4 || scan.resolved_ip || 'N/A')}</strong></div>
        <div class="meta-item">RESOLVED IPV6: <strong>${escapeHtml(scan.dns?.ipv6 || 'Not detected')}</strong></div>
        <div class="meta-item">DNS STATUS: <strong style="color: ${scan.dns?.status === 'FAILED' ? 'var(--critical)' : 'var(--low)'};">${escapeHtml(scan.dns?.status || 'SUCCESS')}</strong></div>
      </div>
      ${exposureTableHtml}
    </section>

    <!-- 4. Key Observations -->
    <section class="section">
      <div class="section-title">04 // KEY AUDIT OBSERVATIONS</div>
      ${findings.length === 0 ? `
        <p style="color: var(--low); font-weight: bold;">[POSITIVE ASSURANCE] Zero security vulnerabilities or misconfigurations discovered across evaluated endpoints.</p>
      ` : `
        <table>
          <thead>
            <tr>
              <th style="width: 90px;">SEVERITY</th>
              <th>OBSERVED FINDING</th>
              <th>AFFECTED COMPONENT</th>
              <th style="width: 130px;">OWASP / CWE</th>
            </tr>
          </thead>
          <tbody>
            ${findings.slice(0, 8).map(f => `
              <tr>
                <td>${sevBadge(f.severity)}</td>
                <td><strong>${escapeHtml(f.title)}</strong></td>
                <td style="color: var(--primary);">${escapeHtml(f.affected_component || f.scanner)}</td>
                <td>${escapeHtml(f.owasp.split('-')[0])} &bull; ${escapeHtml(f.cwe || 'CWE-693')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `}
    </section>

    <!-- 4. Ranked Remediation Priority -->
    <section class="section">
      <div class="section-title">04 // PRIORITIZED REMEDIATION ROADMAP</div>
      <p style="color: var(--text-muted); margin-bottom: 8px;">Remediation tasks ordered deterministically by severity weighting, confidence, and target exposure:</p>
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">PRIORITY</th>
            <th style="width: 90px;">SEVERITY</th>
            <th>TARGET ISSUE</th>
            <th>ACTIONABLE DEFENSIVE REMEDIATION</th>
          </tr>
        </thead>
        <tbody>
          ${rankedFindings.map((f, i) => `
            <tr>
              <td style="font-weight: bold; color: var(--primary);">#${i + 1}</td>
              <td>${sevBadge(f.severity)}</td>
              <td><strong>${escapeHtml(f.title)}</strong></td>
              <td style="font-size: 10.5px;">${escapeHtml(f.remediation)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </section>

    <!-- 5. Detailed Findings -->
    <section class="section">
      <div class="section-title">05 // DETAILED VULNERABILITY FINDINGS (${findings.length})</div>
      ${findings.length === 0 ? '<p style="color: var(--text-muted);">No findings recorded.</p>' : findingsHtml}
    </section>

    <!-- 6. Attack Surface Inventory -->
    <section class="section">
      <div class="section-title">06 // ATTACK SURFACE ENUMERATION</div>
      <div class="exec-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 12px;">
        <div class="exec-card"><div class="exec-label">EVALUATED ENDPOINTS</div><div class="exec-val" style="font-size: 18px;">${inv.endpoints?.length || scan.pages_scanned}</div></div>
        <div class="exec-card"><div class="exec-label">INPUT FORMS DISCOVERED</div><div class="exec-val" style="font-size: 18px;">${inv.forms_count || (inv.forms?.length || 0)}</div></div>
        <div class="exec-card"><div class="exec-label">OBSERVED PARAMETERS</div><div class="exec-val" style="font-size: 18px;">${inv.parameters?.length || 0}</div></div>
      </div>
      ${(inv.endpoints && inv.endpoints.length > 0) ? `
        <div class="prop-label">DISCOVERED SAME-ORIGIN ENDPOINTS:</div>
        <ul class="ref-list" style="max-height: 120px; overflow-y: auto;">
          ${inv.endpoints.slice(0, 20).map((e: string) => `<li>${escapeHtml(e)}</li>`).join('')}
        </ul>
      ` : ''}
    </section>

    <!-- 7. Technology Observations -->
    <section class="section">
      <div class="section-title">07 // FINGERPRINTED TECHNOLOGIES</div>
      ${allTech.length === 0 ? '<p style="color: var(--text-muted);">No distinct third-party technologies or server headers disclosed.</p>' : `
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
          ${allTech.map(t => `<span class="badge badge-info" style="font-size: 11px; padding: 4px 8px;">${escapeHtml(t)}</span>`).join('')}
        </div>
      `}
    </section>

    <!-- 8. Assessment Limitations -->
    <section class="section">
      <div class="section-title">08 // OPERATIONAL ASSESSMENT LIMITATIONS</div>
      <ul class="ref-list">
        ${limitations.map(lim => `<li style="color: var(--text-bright);">${escapeHtml(lim)}</li>`).join('')}
      </ul>
    </section>

    <!-- Footer -->
    <footer style="text-align: center; font-size: 10px; color: var(--text-muted); margin-top: 30px; padding-top: 15px; border-top: 1px solid var(--panel-border);">
      CONFIDENTIAL &bull; AUTHORIZED DEFENSIVE CYBERSECURITY ASSESSMENT &bull; NAYVISTA SHIELD (NAYVISTA TECHNOLOGIES)
    </footer>
  </div>
</body>
</html>`;
  }
}

export const reportService = new ReportService();
