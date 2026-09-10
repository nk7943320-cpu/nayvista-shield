import React from 'react';
import { Terminal, AlertOctagon, AlertTriangle, Info, CheckCircle2, Layers, Globe, FileText, Compass, Zap, CheckSquare, TrendingUp } from 'lucide-react';
import { ScanRecord, Finding, Severity } from '../types';
import { ScoreGauge } from './ScoreGauge';

interface DashboardOverviewProps {
  scan: ScanRecord;
  findings: Finding[];
  onOpenReport: () => void;
  onViewFindings: () => void;
  onViewSurface: () => void;
  onViewRemediation: () => void;
}

const severityWeight: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  scan,
  findings,
  onOpenReport,
  onViewFindings,
  onViewSurface,
  onViewRemediation,
}) => {
  const counts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  };

  // Group by OWASP category
  const owaspStats = findings.reduce<Record<string, number>>((acc, f) => {
    const key = f.owasp || 'Other';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  // Top remediation priority findings
  const topRemediations = [...findings]
    .sort((a, b) => {
      const diff = (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
      if (diff !== 0) return diff;
      return (b.affected_urls?.length || 1) - (a.affected_urls?.length || 1);
    })
    .slice(0, 4);

  return (
    <div className="space-y-6">
      {/* Top Banner with Target & Actions */}
      <div className="bg-[#0A0A0A] border-2 border-border p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-bold text-primary uppercase tracking-widest mb-1.5">
            <Globe className="w-4 h-4" />
            <span>AUDIT TARGET // SAME-ORIGIN BOUNDARY</span>
            <span className="text-[#555]">|</span>
            <span className="text-[#38D39F] font-mono font-bold">MODE: {scan.mode || 'DEFENSIVE / SAFE'}</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl sm:text-2xl font-extrabold text-[#FFF8DB] tracking-wide font-mono">
              {scan.target_hostname}
            </h2>
            {scan.resolved_ip && scan.resolved_ip !== 'N/A' && (
              <span className="px-2 py-0.5 border border-border bg-[#050505] text-[#C7B988] text-[11px] font-mono">
                IP: {scan.resolved_ip}
              </span>
            )}
            {scan.posture === 'LIMITED' && (
              <span className="px-2 py-0.5 border border-amber-500 bg-amber-950/50 text-amber-300 text-[11px] font-bold font-mono">
                [POSTURE: LIMITED / PARTIAL]
              </span>
            )}
            {scan.posture === 'RESTRICTED' && (
              <span className="px-2 py-0.5 border border-amber-500 bg-amber-950/50 text-amber-300 text-[11px] font-bold font-mono">
                [POSTURE: RESTRICTED / WAF]
              </span>
            )}
            {scan.posture === 'DEGRADED' && (
              <span className="px-2 py-0.5 border border-red-500 bg-red-950/50 text-red-300 text-[11px] font-bold font-mono">
                [POSTURE: DEGRADED / SERVER ERROR]
              </span>
            )}
            {(!scan.posture || scan.posture === 'ASSESSED') && (
              <span className="px-2 py-0.5 border border-lime-500/60 bg-lime-950/40 text-lime-400 text-[11px] font-bold font-mono">
                [POSTURE: ASSESSED]
              </span>
            )}
          </div>
          <p className="text-xs text-[#A89F82] font-mono mt-0.5 break-all">{scan.target_url}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={onViewRemediation}
            className="px-3.5 py-2 bg-[#121212] hover:bg-[#1C1805] text-[#FFF8DB] hover:text-primary border border-border hover:border-primary text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 transition cursor-pointer font-mono"
          >
            <CheckSquare className="w-4 h-4 text-primary" />
            <span>Remediation Tasks</span>
          </button>

          <button
            onClick={onOpenReport}
            className="px-3.5 py-2 bg-[#121212] hover:bg-[#1C1805] text-[#FFF8DB] hover:text-primary border border-border hover:border-primary text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 transition cursor-pointer font-mono"
          >
            <FileText className="w-4 h-4 text-primary" />
            <span>Export Report</span>
          </button>

          <button
            onClick={onViewFindings}
            className="px-3.5 py-2 bg-primary hover:bg-[#FFE033] text-black border border-primary text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 transition cursor-pointer font-mono shadow-[0_0_15px_rgba(255,212,0,0.2)]"
          >
            <span>Inspect ({findings.length}) Findings</span>
          </button>
        </div>
      </div>

      {/* Assessment Limited Partial Scan Banner */}
      {(scan.is_limited || scan.posture === 'LIMITED' || (scan.limitations && scan.limitations.length > 0)) && (
        <div className="bg-[#120F05] border-2 border-amber-500/80 p-5 sm:p-6 space-y-4 shadow-xl">
          <div className="flex flex-wrap items-center justify-between border-b border-amber-500/30 pb-3 gap-2">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <span className="text-sm font-extrabold tracking-widest uppercase text-amber-400 font-mono">
                [ ASSESSMENT LIMITED ]
              </span>
            </div>
            <span className="text-xs font-bold font-mono text-amber-300 bg-amber-950/80 border border-amber-500/50 px-2 py-0.5 uppercase tracking-wider">
              STATUS: COMPLETED WITH LIMITATIONS
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1.5">
              <div className="text-[#A89F82]">
                <span className="text-amber-400 font-bold">TARGET:</span> {scan.target_url}
              </div>
              <div className="text-[#A89F82]">
                <span className="text-amber-400 font-bold">REASON:</span>{' '}
                <span className="text-[#FFF8DB]">
                  {scan.limitations?.[0]?.description || scan.limitations?.[0]?.reason || scan.error_message || 'Target could not be reached (connection timed out or host unreachable).'}
                </span>
              </div>
            </div>

            <div className="space-y-2 bg-[#0A0802] p-3 border border-amber-500/20">
              <div className="flex items-center justify-between">
                <span className="text-amber-400 font-bold">SECURITY SCORE:</span>
                <span className="text-[#FFF8DB] font-bold">
                  {scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : 'N/A'}{' '}
                  <span className="text-[#888] font-normal font-sans text-[11px]">(Insufficient evidence)</span>
                </span>
              </div>
              <div>
                <div className="flex items-center justify-between text-[11px] mb-1">
                  <span className="text-amber-400 font-bold">ASSESSMENT COVERAGE:</span>
                  <span className="text-[#FFF8DB] font-bold">
                    {scan.coverage?.coverage_pct ?? scan.coverage?.percentage ?? 0}%{' '}
                    <span className="text-[#888] font-normal">
                      ({scan.coverage?.completed_stages ?? 0} / {scan.coverage?.total_stages ?? 14} stages completed)
                    </span>
                  </span>
                </div>
                {/* Visual progress bar */}
                <div className="w-full bg-[#201A06] h-2 border border-amber-500/30 overflow-hidden">
                  <div
                    className="bg-amber-400 h-full transition-all duration-300"
                    style={{ width: `${scan.coverage?.coverage_pct ?? scan.coverage?.percentage ?? 0}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Assessment Limitations List */}
          {scan.limitations && scan.limitations.length > 0 && (
            <div className="pt-2 border-t border-amber-500/20">
              <span className="text-[11px] font-bold uppercase tracking-wider text-amber-400 font-mono block mb-1.5">
                Encountered Limitations:
              </span>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                {scan.limitations.map((lim, idx) => (
                  <li key={idx} className="flex items-start space-x-2 text-[#E8DCC0] bg-[#1A1507] p-2 border border-amber-500/20">
                    <span className="text-amber-400 font-bold">⚠</span>
                    <div>
                      <span className="font-bold text-amber-300">{lim.stage}:</span>{' '}
                      <span>{lim.description || lim.reason || lim.code}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Stage Status Checklist */}
          {scan.stage_status && Object.keys(scan.stage_status).length > 0 && (
            <div className="pt-2 border-t border-amber-500/20">
              <span className="text-[11px] font-bold uppercase tracking-wider text-amber-400 font-mono block mb-1.5">
                Stage Execution Matrix:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 text-[11px] font-mono">
                {Object.entries(scan.stage_status).map(([stageName, stageState]) => {
                  const isCompleted = stageState === 'COMPLETED';
                  const isLimited = stageState === 'LIMITED';
                  const isSkipped = stageState === 'SKIPPED';
                  return (
                    <div
                      key={stageName}
                      className={`p-1.5 border flex items-center justify-between ${
                        isCompleted
                          ? 'bg-[#0A1A0F] border-green-800/60 text-green-300'
                          : isLimited
                          ? 'bg-[#211A05] border-amber-700/60 text-amber-300'
                          : isSkipped
                          ? 'bg-[#141414] border-gray-800 text-gray-400'
                          : 'bg-[#210A0A] border-red-800 text-red-400'
                      }`}
                    >
                      <span className="truncate pr-1">{stageName}</span>
                      <span className="font-bold text-[10px]">
                        {isCompleted ? '✓ OK' : isLimited ? '⚠ LIM' : isSkipped ? 'SKIP' : 'FAIL'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <p className="text-[11px] text-[#888] font-mono italic pt-1">
            Note: Assessment limitations do not by themselves indicate a security vulnerability. Probing was halted or skipped safely to prevent false conclusions.
          </p>
        </div>
      )}

      {/* Top Grid: Score Gauge + Severity Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Score Card */}
        <div className="md:col-span-4 bg-[#0A0A0A] border border-border border-l-4 border-l-primary p-5 flex flex-col justify-between">
          <div>
            <div className="text-xs font-bold uppercase text-primary tracking-wider font-mono">
              [SECURITY SCORE]
            </div>
            <p className="text-[11px] text-[#7A7256] mt-0.5">Calibrated risk deductions from confirmed findings</p>
          </div>

          <ScoreGauge
            score={scan.security_score}
            grade={scan.grade}
            riskLevel={scan.risk_level}
          />

          <div className="text-center pt-3 border-t border-border text-xs text-[#A89F82] font-mono">
            Duration: <span className="text-primary font-bold">{scan.duration_seconds}s</span> &bull; Scanned: <span className="text-[#FFF8DB] font-bold">{scan.pages_scanned} pages</span>
          </div>
        </div>

        {/* Severity Metrics Cards */}
        <div className="md:col-span-8 grid grid-cols-2 sm:grid-cols-3 gap-3">
          <div className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-[#FF4444] transition">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-[#FF4444] font-mono">CRITICAL</span>
              <AlertOctagon className="w-4 h-4 text-[#FF4444]" />
            </div>
            <div className="text-2xl font-extrabold text-[#FFA3A3] mt-3 font-mono">{counts.CRITICAL}</div>
            <div className="text-[10px] text-[#7A7256] mt-1 font-mono">Immediate risk exposure</div>
          </div>

          <div className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-[#FF8800] transition">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-[#FF8800] font-mono">HIGH</span>
              <AlertTriangle className="w-4 h-4 text-[#FF8800]" />
            </div>
            <div className="text-2xl font-extrabold text-[#FFBA66] mt-3 font-mono">{counts.HIGH}</div>
            <div className="text-[10px] text-[#7A7256] mt-1 font-mono">High exploitability</div>
          </div>

          <div className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-primary transition">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-primary font-mono">MEDIUM</span>
              <AlertTriangle className="w-4 h-4 text-primary" />
            </div>
            <div className="text-2xl font-extrabold text-[#FFE466] mt-3 font-mono">{counts.MEDIUM}</div>
            <div className="text-[10px] text-[#7A7256] mt-1 font-mono">Configuration defect</div>
          </div>

          <div className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-[#84CC16] transition">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-[#84CC16] font-mono">LOW</span>
              <Info className="w-4 h-4 text-[#84CC16]" />
            </div>
            <div className="text-2xl font-extrabold text-[#B1E868] mt-3 font-mono">{counts.LOW}</div>
            <div className="text-[10px] text-[#7A7256] mt-1 font-mono">Defense-in-depth gap</div>
          </div>

          <div className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-[#858E96] transition">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-[#858E96] font-mono">INFO</span>
              <CheckCircle2 className="w-4 h-4 text-[#858E96]" />
            </div>
            <div className="text-2xl font-extrabold text-[#BDC5CC] mt-3 font-mono">{counts.INFO}</div>
            <div className="text-[10px] text-[#7A7256] mt-1 font-mono">Audited indicators</div>
          </div>

          <div
            onClick={onViewSurface}
            className="bg-[#0A0A0A] border border-border p-4 flex flex-col justify-between hover:border-primary cursor-pointer transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-primary font-mono">ATTACK SURFACE</span>
              <Layers className="w-4 h-4 text-primary group-hover:scale-110 transition" />
            </div>
            <div className="text-2xl font-extrabold text-[#FFF8DB] mt-3 font-mono">
              {scan.inventory?.endpoints?.length ?? scan.pages_scanned ?? 0}
            </div>
            <div className="text-[10px] text-[#A89F82] mt-1 font-mono group-hover:text-primary transition">
              View endpoints &rarr;
            </div>
          </div>
        </div>
      </div>

      {/* Host & Network Service Exposure Panel */}
      <div className="bg-[#0A0A0A] border border-border p-5 shadow-sm">
        <div className="flex items-center justify-between border-b border-border pb-3 mb-4">
          <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-primary font-mono">
            <Globe className="w-4 h-4" />
            <span>HOST &amp; NETWORK SERVICE EXPOSURE</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-[11px] font-mono text-[#7A7256]">MODE:</span>
            <span className="text-[11px] font-bold font-mono text-[#38D39F] bg-[#0E2818] border border-[#165030] px-2 py-0.5">
              {scan.mode || 'DEFENSIVE / SAFE'}
            </span>
          </div>
        </div>

        {/* DNS Resolution Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-4 text-xs font-mono">
          <div className="bg-[#050505] border border-border p-2.5">
            <span className="text-[10px] text-[#7A7256] uppercase block">TARGET HOST</span>
            <span className="text-[#FFF8DB] font-bold truncate block mt-0.5">{scan.target_hostname}</span>
          </div>
          <div className="bg-[#050505] border border-border p-2.5">
            <span className="text-[10px] text-[#7A7256] uppercase block">RESOLVED IPV4</span>
            <span className="text-primary font-bold block mt-0.5">{scan.dns?.ipv4 || scan.resolved_ip || 'N/A'}</span>
          </div>
          <div className="bg-[#050505] border border-border p-2.5">
            <span className="text-[10px] text-[#7A7256] uppercase block">RESOLVED IPV6</span>
            <span className="text-[#A89F82] block mt-0.5">{scan.dns?.ipv6 || 'Not detected'}</span>
          </div>
          <div className="bg-[#050505] border border-border p-2.5">
            <span className="text-[10px] text-[#7A7256] uppercase block">DNS STATUS</span>
            <span className={`font-bold block mt-0.5 ${scan.dns?.status === 'FAILED' ? 'text-[#FF4444]' : 'text-lime-400'}`}>
              {scan.dns?.status || 'SUCCESS'}
            </span>
          </div>
        </div>

        {/* Curated Service Port Exposure Table */}
        {scan.network_exposure && scan.network_exposure.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border border-border">
              <thead className="bg-[#121004] text-primary border-b border-border text-[11px] uppercase">
                <tr>
                  <th className="p-2.5">Port</th>
                  <th className="p-2.5">Service</th>
                  <th className="p-2.5">State</th>
                  <th className="p-2.5">Exposure</th>
                  <th className="p-2.5">Risk Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scan.network_exposure.map((exp) => (
                  <tr key={exp.port} className="hover:bg-[#0E0E0E] transition">
                    <td className="p-2.5 font-bold text-[#FFF8DB]">TCP/{exp.port}</td>
                    <td className="p-2.5 text-[#C7B988]">{exp.service}</td>
                    <td className="p-2.5">
                      <span className={`px-2 py-0.5 text-[10px] font-bold uppercase ${
                        exp.state === 'OPEN'
                          ? 'bg-[#0E2818] border border-[#165030] text-[#38D39F]'
                          : 'bg-[#161616] border border-[#2B2B2B] text-[#777]'
                      }`}>
                        {exp.state}
                      </span>
                    </td>
                    <td className="p-2.5 text-[#A89F82]">{exp.exposure || '-'}</td>
                    <td className="p-2.5">
                      <span className={`px-2 py-0.5 text-[10px] font-bold uppercase ${
                        exp.risk === 'HIGH'
                          ? 'bg-[#2E0B0B] border border-[#7A1C1C] text-[#FFA3A3]'
                          : exp.risk === 'REVIEW'
                          ? 'bg-[#2E1C0B] border border-[#7A451C] text-[#FFBA66]'
                          : exp.risk === 'EXPECTED'
                          ? 'bg-[#0E2818] border border-[#165030] text-[#38D39F]'
                          : 'text-[#666]'
                      }`}>
                        {exp.risk}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-[#7A7256] font-mono">No network port exposure observations recorded.</p>
        )}
      </div>

      {/* Top Remediation Priorities Card */}
      {topRemediations.length > 0 && (
        <div className="bg-[#0A0A0A] border border-border p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-primary flex items-center space-x-2 font-mono">
              <Compass className="w-4 h-4" />
              <span>TOP REMEDIATION PRIORITIES (BY SEVERITY & IMPACT)</span>
            </h3>
            <button
              onClick={onViewRemediation}
              className="text-[11px] text-primary hover:underline font-mono cursor-pointer"
            >
              [OPEN FULL CHECKLIST &rarr;]
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {topRemediations.map((f, idx) => (
              <div key={f.id || idx} className="bg-[#050505] border border-border p-3 flex items-start space-x-3">
                <span className="h-5 w-5 border border-primary text-primary font-mono font-bold text-xs flex items-center justify-center flex-shrink-0 mt-0.5">
                  #{idx + 1}
                </span>
                <div className="min-w-0">
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-bold text-primary font-mono">[{f.severity}]</span>
                    <span className="text-xs font-bold text-[#FFF8DB] truncate font-mono">{f.title}</span>
                  </div>
                  <div className="text-[11px] text-[#A89F82] mt-0.5 line-clamp-2 font-mono">{f.remediation}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Executive Summary Card */}
      <div className="bg-[#0A0A0A] border border-border p-5 sm:p-7 shadow-sm">
        <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-primary mb-3 font-mono">
          <Zap className="w-4 h-4" />
          <span>AI VULNERABILITY ANALYSIS &bull; EXECUTIVE SUMMARY</span>
        </div>

        <div className="space-y-3 font-mono">
          <p className="text-sm text-[#FFF8DB] leading-relaxed font-medium">
            {scan.ai_analysis?.executive_summary || 'Analysis completed by NayVista Shield defensive engine.'}
          </p>
          {scan.ai_analysis?.risk_narrative && (
            <p className="text-xs text-[#C7B988] leading-relaxed">
              {scan.ai_analysis.risk_narrative}
            </p>
          )}
        </div>
      </div>

      {/* OWASP Top 10 Breakdown */}
      <div className="bg-[#0A0A0A] border border-border p-5 shadow-sm">
        <h3 className="text-xs font-bold uppercase tracking-wider text-primary mb-3.5 font-mono">
          OWASP TOP 10 CATEGORY DISTRIBUTION
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
          {Object.entries(owaspStats).map(([cat, count]) => (
            <div key={cat} className="bg-[#050505] border border-border p-2.5 flex items-center justify-between">
              <span className="text-xs text-[#C7B988] truncate mr-2 font-mono">{cat}</span>
              <span className="text-xs font-bold px-2 py-0.5 border border-primary/40 bg-primary/10 text-primary font-mono">
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
