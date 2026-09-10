"""
NayVista Shield - Standalone Report Generator (Python)
Generates structured JSON reports and standalone printable HTML reports for CLI and standalone use.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List

def generate_json_report(scan_result: Dict[str, Any]) -> str:
    """Formats the scan result dictionary as indented JSON."""
    scoring = scan_result.get("scoring", {})
    posture = scan_result.get("posture", "ASSESSED")
    assessment_status = scan_result.get("assessment_status", "COMPLETED_WITH_LIMITATIONS" if posture == "LIMITED" else "COMPLETED")
    coverage = scan_result.get("coverage", {})
    if not coverage:
        coverage = {
            "completed_stages": 14 if posture != "LIMITED" else 5,
            "total_stages": 14,
            "percentage": 100 if posture != "LIMITED" else 36,
            "status": assessment_status,
        }

    report_data = {
        "assessment_status": assessment_status,
        "mode": scan_result.get("mode", "DEFENSIVE / SAFE"),
        "resolved_ip": scan_result.get("resolved_ip", "N/A"),
        "dns": scan_result.get("dns", {}),
        "network_exposure": scan_result.get("network_exposure", []),
        "posture": posture,
        "security_score": scoring.get("score"),
        "coverage": coverage,
        "stage_status": scan_result.get("stage_status", {}),
        "limitations": scan_result.get("limitations", []),
        "scoring": scoring,
        "findings": scan_result.get("findings", []),
        "inventory": scan_result.get("inventory", {}),
        "technologies": scan_result.get("technologies", {}),
        "scan": scan_result,
    }
    return json.dumps(report_data, indent=2)

def generate_html_report(scan_result: Dict[str, Any]) -> str:
    """Generates a standalone, print-styled HTML audit report."""
    target = scan_result.get("target", "Target")
    hostname = scan_result.get("hostname", target)
    scoring = scan_result.get("scoring", {})
    posture = scan_result.get("posture", "ASSESSED")
    assessment_status = scan_result.get("assessment_status", "COMPLETED_WITH_LIMITATIONS" if posture == "LIMITED" else "COMPLETED")
    coverage = scan_result.get("coverage", {})
    stage_status = scan_result.get("stage_status", {})
    limitations = scan_result.get("limitations", [])

    score = scoring.get("score")
    score_display = "N/A" if score is None else str(score)
    grade = scoring.get("grade", "A") if score is not None else "N/A"
    risk_level = scoring.get("risk_level", "LOW") if score is not None else "LIMITED"

    findings = scan_result.get("findings", [])
    duration = scan_result.get("duration_seconds", 0)
    pages_scanned = scan_result.get("pages_scanned", 0)
    technologies = scan_result.get("technologies", {})
    inventory = scan_result.get("inventory", {})
    mode = scan_result.get("mode", "DEFENSIVE / SAFE")
    dns = scan_result.get("dns", {})
    resolved_ipv4 = dns.get("ipv4", scan_result.get("resolved_ip", "Not resolved"))
    resolved_ipv6 = dns.get("ipv6", "Not detected")
    dns_status = dns.get("status", "SUCCESS")
    network_exposure = scan_result.get("network_exposure", [])

    def esc(s: Any) -> str:
        if s is None:
            return ""
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    exposure_rows = ""
    for exp in network_exposure:
        st = exp.get("state", "CLOSED")
        st_color = "#38D39F" if st == "OPEN" else "#777"
        rk = exp.get("risk", "-")
        rk_color = "#FF4B4B" if rk == "HIGH" else ("#FFA726" if rk == "REVIEW" else ("#38D39F" if rk == "EXPECTED" else "#888"))
        exposure_rows += f"""
        <tr>
          <td style="padding: 6px 12px; font-family: monospace; border-bottom: 1px solid #1C1910;">{exp.get('port')}</td>
          <td style="padding: 6px 12px; border-bottom: 1px solid #1C1910;">{esc(exp.get('service'))}</td>
          <td style="padding: 6px 12px; color: {st_color}; font-weight: bold; border-bottom: 1px solid #1C1910;">{esc(st)}</td>
          <td style="padding: 6px 12px; border-bottom: 1px solid #1C1910;">{esc(exp.get('exposure', '-'))}</td>
          <td style="padding: 6px 12px; color: {rk_color}; font-weight: bold; border-bottom: 1px solid #1C1910;">{esc(rk)}</td>
        </tr>
        """

    counts = scoring.get("counts", {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    })

    def sev_badge(sev: str) -> str:
        sev = sev.upper()
        if sev == "CRITICAL":
            return '<span class="badge badge-critical">CRITICAL</span>'
        elif sev == "HIGH":
            return '<span class="badge badge-high">HIGH</span>'
        elif sev == "MEDIUM":
            return '<span class="badge badge-medium">MEDIUM</span>'
        elif sev == "LOW":
            return '<span class="badge badge-low">LOW</span>'
        return '<span class="badge badge-info">INFO</span>'

    findings_html = ""
    for idx, f in enumerate(findings):
        evidence = esc(f.get("evidence", ""))
        findings_html += f"""
        <div class="finding-card">
          <div class="finding-header">
            <div class="finding-title-row">
              <span class="finding-num">#{idx + 1}</span>
              <span class="finding-title">{esc(f.get("title", ""))}</span>
            </div>
            <div class="badges">
              {sev_badge(f.get("severity", "INFO"))}
              <span class="badge badge-subtle">Confidence: {esc(f.get("confidence", "MEDIUM"))}</span>
              <span class="badge badge-owasp">{esc(f.get("owasp", "OWASP"))}</span>
            </div>
          </div>
          <div class="finding-body">
            <p class="finding-desc">{esc(f.get("description", ""))}</p>
            <div class="meta-section">
              <div class="meta-label">Affected Target:</div>
              <div class="code-url">{esc(f.get("url", ""))}</div>
            </div>
            <div class="meta-section">
              <div class="meta-label">Observed Evidence:</div>
              <pre class="evidence-box"><code>{evidence}</code></pre>
            </div>
            <div class="meta-section">
              <div class="meta-label">Security Impact:</div>
              <p class="meta-text">{esc(f.get("impact", ""))}</p>
            </div>
            <div class="meta-section remediation-box">
              <div class="remediation-title">Recommended Remediation:</div>
              <p class="remediation-text">{esc(f.get("remediation", ""))}</p>
            </div>
          </div>
        </div>
        """

    tech_list = []
    for category, items in technologies.items():
        if items:
            tech_list.append(f"<strong>{category.replace('_', ' ').title()}:</strong> {', '.join(items)}")
    tech_html = "<br>".join(tech_list) if tech_list else "<em>No technology signatures observed.</em>"

    coverage_pct = coverage.get("percentage", 100 if posture != "LIMITED" else 0)
    completed_stages = coverage.get("completed_stages", 14 if posture != "LIMITED" else 0)
    total_stages = coverage.get("total_stages", 14)

    limited_panel_html = ""
    if posture == "LIMITED" or limitations:
        stages_rows = ""
        for st_name, st_val in stage_status.items():
            color = "#38D39F" if st_val == "COMPLETED" else ("#FFD400" if st_val == "LIMITED" else ("#777" if st_val == "SKIPPED" else "#FF4444"))
            stages_rows += f"""
            <div style="display: flex; justify-content: space-between; padding: 3px 6px; border-bottom: 1px solid #1C1910; font-size: 11px;">
              <span>{esc(st_name)}</span>
              <span style="color: {color}; font-weight: bold;">{esc(st_val)}</span>
            </div>
            """

        reasons_list = ""
        for lim in limitations:
            reasons_list += f"<li style='margin-bottom: 4px;'><strong>{esc(lim.get('stage', 'Stage'))}:</strong> {esc(lim.get('reason', ''))}</li>"

        limited_panel_html = f"""
        <div style="background: #140F03; border: 1px solid #7A5800; border-left: 4px solid #FFD400; padding: 20px; margin-bottom: 24px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid #382A05; padding-bottom: 8px;">
            <span style="font-weight: 800; color: #FFD400; font-size: 14px;">[ ASSESSMENT LIMITED ]</span>
            <span style="font-size: 11px; color: #C7B988; font-weight: bold;">STATUS: COMPLETED WITH LIMITATIONS</span>
          </div>
          <div style="font-size: 12px; color: #FFF8DB; margin-bottom: 14px;">
            Target could not be reached within the configured timeout or experienced reachability limitations.
            <div style="color: #A89F82; font-size: 11px; margin-top: 4px; font-style: italic;">
              Note: This does not by itself indicate a security vulnerability.
            </div>
          </div>
          <div style="margin-bottom: 14px;">
            <div style="font-size: 11px; font-weight: bold; color: #FFD400; text-transform: uppercase; margin-bottom: 6px;">Assessment Coverage: {completed_stages} / {total_stages} stages completed ({coverage_pct}%)</div>
            <div style="background: #000; border: 1px solid #26200A; height: 10px; width: 100%; border-radius: 2px; overflow: hidden;">
              <div style="background: #FFD400; height: 100%; width: {coverage_pct}%;"></div>
            </div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px;">
            <div style="background: #0A0A0A; border: 1px solid #26200A; padding: 10px;">
              <div style="font-size: 10px; color: #7A7256; text-transform: uppercase; margin-bottom: 6px; font-weight: bold;">Stage Status Breakdown</div>
              {stages_rows}
            </div>
            <div style="background: #0A0A0A; border: 1px solid #26200A; padding: 10px;">
              <div style="font-size: 10px; color: #7A7256; text-transform: uppercase; margin-bottom: 6px; font-weight: bold;">Recorded Target Limitations</div>
              <ul style="font-size: 11px; color: #D4C9A8; padding-left: 16px;">
                {reasons_list if reasons_list else "<li>Target reachability limitations recorded.</li>"}
              </ul>
            </div>
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NayVista Shield Security Audit Report - {esc(hostname)}</title>
  <style>
    :root {{
      --bg: #050505;
      --card-bg: #0C0C0C;
      --border: #26200A;
      --border-bright: #FFD400;
      --text: #FFF8DB;
      --text-muted: #9E9575;
      --accent: #FFD400;
      --critical: #FF4444;
      --high: #FF8800;
      --medium: #FFD400;
      --low: #84CC16;
      --info: #858E96;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'JetBrains Mono', 'SF Mono', Consolas, Menlo, Monaco, monospace;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 40px 20px;
    }}
    .container {{ max-width: 980px; margin: 0 auto; }}
    .header {{
      border-bottom: 2px solid var(--accent);
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }}
    .logo-badge {{
      font-size: 24px;
      font-weight: 800;
      color: var(--accent);
      letter-spacing: 0.05em;
    }}
    .meta-subtitle {{
      color: var(--text-muted);
      font-size: 13px;
      margin-top: 4px;
      letter-spacing: 0.02em;
    }}
    .score-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 4px;
      padding: 24px;
      margin-bottom: 28px;
      display: flex;
      justify-content: space-around;
      align-items: center;
      text-align: center;
    }}
    .score-num {{ font-size: 42px; font-weight: 800; color: var(--accent); }}
    .score-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; letter-spacing: 0.06em; }}
    .stats-row {{ display: flex; gap: 12px; margin-bottom: 28px; }}
    .stat-pill {{
      flex: 1;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 12px;
      text-align: center;
    }}
    .stat-pill .val {{ font-size: 24px; font-weight: 800; }}
    .stat-pill .lbl {{ font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }}
    .c-crit {{ color: var(--critical); }}
    .c-high {{ color: var(--high); }}
    .c-med {{ color: var(--medium); }}
    .c-low {{ color: var(--low); }}
    .c-info {{ color: var(--info); }}
    .section-title {{
      font-size: 16px;
      font-weight: 700;
      margin: 32px 0 16px;
      border-left: 3px solid var(--accent);
      padding-left: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--accent);
    }}
    .info-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 16px 20px;
      margin-bottom: 24px;
      font-size: 13px;
    }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 20px;
      margin-bottom: 18px;
      page-break-inside: avoid;
    }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
      gap: 12px;
    }}
    .finding-title-row {{ display: flex; align-items: baseline; gap: 8px; flex: 1; }}
    .finding-num {{ color: var(--accent); font-weight: 800; font-size: 14px; }}
    .finding-title {{ font-size: 15px; font-weight: 700; color: #FFF8DB; }}
    .badges {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .badge {{
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 2px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .badge-critical {{ background: #3A0D0D; color: #FF6666; border: 1px solid #7A1A1A; }}
    .badge-high {{ background: #381A05; color: #FFA044; border: 1px solid #7A3B0F; }}
    .badge-medium {{ background: #332600; color: #FFD400; border: 1px solid #6E5400; }}
    .badge-low {{ background: #0F2908; color: #84CC16; border: 1px solid #235415; }}
    .badge-info {{ background: #16181B; color: #9EABB8; border: 1px solid #2E343D; }}
    .badge-subtle {{ background: #1A1812; color: #C7B988; border: 1px solid var(--border); }}
    .badge-owasp {{ background: #14120A; color: #E0CA82; border: 1px solid #383015; }}
    .finding-desc {{ font-size: 13px; color: #D4C9A8; line-height: 1.6; margin-bottom: 12px; }}
    .meta-section {{ margin-top: 10px; }}
    .meta-label {{ font-size: 10px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px; letter-spacing: 0.06em; }}
    .code-url {{ font-size: 12px; color: var(--accent); word-break: break-all; }}
    .evidence-box {{
      background: #030303;
      border: 1px solid var(--border);
      border-radius: 2px;
      padding: 10px 12px;
      font-size: 11px;
      color: #E6DCB8;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .meta-text {{ font-size: 13px; color: #D4C9A8; }}
    .remediation-box {{
      background: #121004;
      border-left: 3px solid var(--accent);
      border-radius: 0 2px 2px 0;
      padding: 12px 14px;
      margin-top: 14px;
    }}
    .remediation-title {{ font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .remediation-text {{ font-size: 12px; color: #D4C9A8; line-height: 1.6; }}
    .footer {{
      margin-top: 48px;
      border-top: 1px solid var(--border);
      padding-top: 20px;
      text-align: center;
      font-size: 11px;
      color: var(--text-muted);
      letter-spacing: 0.03em;
    }}
    @media print {{
      body {{ background: #fff !important; color: #000 !important; padding: 0; }}
      .header {{ border-bottom-color: #000; }}
      .logo-badge {{ color: #000; }}
      .meta-subtitle, .footer {{ color: #555; }}
      .score-card, .finding-card, .stat-pill, .info-card {{
        background: #fff !important; border: 1px solid #bbb !important; color: #000 !important;
      }}
      .score-num {{ color: #000; }}
      .code-url, .remediation-title, .section-title {{ color: #000 !important; }}
      .evidence-box {{ background: #f5f5f5 !important; color: #000 !important; border: 1px solid #ddd; }}
      .remediation-box {{ background: #f9f9f9 !important; border-left-color: #000; }}
      .remediation-text, .meta-text, .finding-desc {{ color: #111 !important; }}
      .badge {{ border: 1px solid #999 !important; }}
      .badge-critical {{ background: #fee !important; color: #900 !important; }}
      .badge-high {{ background: #fff0e6 !important; color: #a30 !important; }}
      .badge-medium {{ background: #fffde6 !important; color: #760 !important; }}
      .badge-low {{ background: #eefbee !important; color: #161 !important; }}
      .badge-info {{ background: #eee !important; color: #444 !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="logo-badge">███ NAYVISTA SHIELD ███</div>
        <div class="meta-subtitle">AI-Assisted Web Security Assessment &bull; NayVista Technologies</div>
        <div class="badge badge-owasp" style="display:inline-block; margin-top: 5px; font-weight: bold;">MODE: {esc(mode)}</div>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 13px; font-weight: 700; color: var(--accent);">{esc(hostname)}</div>
        <div class="meta-subtitle">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
      </div>
    </div>

    {limited_panel_html}

    <div class="score-card">
      <div>
        <div class="score-num">{score_display}</div>
        <div class="score-label">Security Score (0-100)</div>
      </div>
      <div>
        <div class="score-num">{esc(grade)}</div>
        <div class="score-label">Security Grade</div>
      </div>
      <div>
        <div class="score-num" style="color: {'var(--critical)' if risk_level == 'CRITICAL' else ('var(--high)' if risk_level == 'HIGH' else ('var(--medium)' if risk_level == 'LIMITED' else 'var(--low)'))}">{esc(risk_level)}</div>
        <div class="score-label">Overall Risk Level</div>
      </div>
      <div>
        <div class="score-num">{pages_scanned}</div>
        <div class="score-label">Pages Audited ({duration}s)</div>
      </div>
    </div>

    <div class="stats-row">
      <div class="stat-pill"><div class="val c-crit">{counts.get('CRITICAL', 0)}</div><div class="lbl">Critical</div></div>
      <div class="stat-pill"><div class="val c-high">{counts.get('HIGH', 0)}</div><div class="lbl">High</div></div>
      <div class="stat-pill"><div class="val c-med">{counts.get('MEDIUM', 0)}</div><div class="lbl">Medium</div></div>
      <div class="stat-pill"><div class="val c-low">{counts.get('LOW', 0)}</div><div class="lbl">Low</div></div>
      <div class="stat-pill"><div class="val c-info">{counts.get('INFO', 0)}</div><div class="lbl">Info</div></div>
    </div>

    <h2 class="section-title">Host & Network Exposure</h2>
    <div class="info-card" style="margin-bottom: 20px;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 14px;">
        <div><strong>Hostname:</strong> {esc(hostname)}</div>
        <div><strong>Resolved IPv4:</strong> <span style="font-family: monospace;">{esc(resolved_ipv4)}</span></div>
        <div><strong>Resolved IPv6:</strong> <span style="font-family: monospace;">{esc(resolved_ipv6)}</span></div>
        <div><strong>DNS Status:</strong> <span style="color: {'#38D39F' if dns_status == 'SUCCESS' else '#FF4B4B'}; font-weight: bold;">{esc(dns_status)}</span></div>
      </div>
      <table style="width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; text-align: left;">
        <thead>
          <tr style="border-bottom: 2px solid var(--border); color: var(--accent);">
            <th style="padding: 6px 12px;">Port</th>
            <th style="padding: 6px 12px;">Service</th>
            <th style="padding: 6px 12px;">State</th>
            <th style="padding: 6px 12px;">Exposure</th>
            <th style="padding: 6px 12px;">Risk</th>
          </tr>
        </thead>
        <tbody>
          {exposure_rows}
        </tbody>
      </table>
    </div>

    <h2 class="section-title">Attack Surface & Technology Profile</h2>
    <div class="info-card">
      <p style="margin-bottom: 8px;"><strong>Discovered Endpoints:</strong> {len(inventory.get('endpoints', []))} &nbsp;|&nbsp; <strong>Dynamic Parameters:</strong> {len(inventory.get('parameters', []))} &nbsp;|&nbsp; <strong>Forms Audited:</strong> {len(inventory.get('forms', []))}</p>
      <div>{tech_html}</div>
    </div>

    <h2 class="section-title">Vulnerability Findings ({len(findings)})</h2>
    {findings_html}

    <div class="footer">
      NayVista Shield &bull; AI-Assisted Web Security Assessment &bull; NayVista Technologies &bull; Strictly Scoped Authorized Assessment
    </div>
  </div>
</body>
</html>"""
