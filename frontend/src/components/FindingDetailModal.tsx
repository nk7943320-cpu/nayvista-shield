import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, ExternalLink, Copy, Check, AlertTriangle, Info, AlertOctagon } from 'lucide-react';
import { Finding, FindingStatus, Severity } from '../types';

interface FindingDetailModalProps {
  finding: Finding;
  allFindings: Finding[];
  scanId: string;
  onClose: () => void;
  onStatusChange?: (findingId: string, status: FindingStatus) => void;
}

const severityBadgeStyles: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-[#2B0B0B]', text: 'text-[#FF6666]', border: 'border-[#5C1414]' },
  HIGH: { bg: 'bg-[#2E1400]', text: 'text-[#FFA044]', border: 'border-[#5C2800]' },
  MEDIUM: { bg: 'bg-[#292200]', text: 'text-[#FFD400]', border: 'border-[#5C4D00]' },
  LOW: { bg: 'bg-[#102404]', text: 'text-[#84CC16]', border: 'border-[#254E0A]' },
  INFO: { bg: 'bg-[#14171A]', text: 'text-[#9EABB8]', border: 'border-[#2B3036]' },
};

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  allFindings,
  scanId,
  onClose,
  onStatusChange,
}) => {
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState<FindingStatus>(finding.status || 'OPEN');
  const [isUpdating, setIsUpdating] = useState(false);

  const style = severityBadgeStyles[finding.severity] || severityBadgeStyles.INFO;

  // Filter truly related findings (same category, or same affected component, excluding self)
  const relatedFindings = allFindings.filter(
    f => f.id !== finding.id && (f.category === finding.category || f.owasp === finding.owasp)
  );

  const handleCopyEvidence = () => {
    navigator.clipboard.writeText(finding.evidence || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleToggleAcceptedRisk = async () => {
    if (!onStatusChange) return;
    const newStatus: FindingStatus = status === 'ACCEPTED_RISK' ? 'OPEN' : 'ACCEPTED_RISK';
    setIsUpdating(true);
    try {
      await onStatusChange(finding.id, newStatus);
      setStatus(newStatus);
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm font-mono animate-in fade-in duration-150">
      <div className="relative w-full max-w-3xl max-h-[90vh] bg-[#0A0A0A] border-2 border-primary flex flex-col shadow-[0_0_30px_rgba(255,212,0,0.25)]">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between px-5 py-3.5 bg-[#121004] border-b border-primary/40">
          <div className="flex items-center space-x-3">
            <span className={`px-2 py-0.5 text-xs font-bold border ${style.bg} ${style.text} ${style.border}`}>
              [{finding.severity}]
            </span>
            <span className="text-xs text-[#A89F82] uppercase tracking-wider">
              INVESTIGATION // {finding.id}
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-[#A89F82] hover:text-primary hover:bg-[#1E1B0A] transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-[#C7B988]">
          {/* Finding Title & Target */}
          <div>
            <h2 className="text-lg font-bold text-[#FFF8DB] leading-snug">
              {finding.title}
            </h2>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px]">
              <span className="text-primary font-bold">TARGET:</span>
              <span className="text-[#FFF8DB] bg-[#141414] px-2 py-0.5 border border-border truncate max-w-md">
                {finding.url}
              </span>
              {finding.affected_component && (
                <span className="text-[#A89F82]">
                  COMPONENT: <strong className="text-primary">{finding.affected_component}</strong>
                </span>
              )}
            </div>
          </div>

          {/* Metadata Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-border/80">
            <div className="bg-[#050505] p-2.5 border border-border">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">CONFIDENCE</div>
              <div className="text-xs font-bold text-[#FFF8DB] mt-0.5">{finding.confidence}</div>
            </div>
            <div className="bg-[#050505] p-2.5 border border-border">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">OWASP CATEGORY</div>
              <div className="text-xs font-bold text-[#FFF8DB] mt-0.5 truncate">{finding.owasp || 'A05:2021'}</div>
            </div>
            <div className="bg-[#050505] p-2.5 border border-border">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">CWE MAPPING</div>
              <div className="text-xs font-bold text-primary mt-0.5">{finding.cwe || 'CWE-693'}</div>
            </div>
            <div className="bg-[#050505] p-2.5 border border-border">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">CURRENT STATUS</div>
              <div className="text-xs font-bold text-[#84CC16] mt-0.5">
                {status === 'ACCEPTED_RISK' ? (
                  <span className="text-amber-400 font-bold">ACCEPTED RISK</span>
                ) : (
                  <span className="text-lime-400 font-bold">OPEN</span>
                )}
              </div>
            </div>
          </div>

          {/* Section 1: What was observed */}
          <div className="space-y-1.5">
            <h3 className="text-[11px] font-bold text-primary uppercase tracking-widest flex items-center space-x-1.5">
              <span>[01] WHAT WAS OBSERVED</span>
            </h3>
            <p className="text-sm text-[#FFF8DB] leading-relaxed bg-[#0D0D0D] p-3 border border-border">
              {finding.description}
            </p>
          </div>

          {/* Section 2: Why it matters */}
          <div className="space-y-1.5">
            <h3 className="text-[11px] font-bold text-[#FFA044] uppercase tracking-widest flex items-center space-x-1.5">
              <span>[02] WHY IT MATTERS (IMPACT & RISK)</span>
            </h3>
            <p className="text-sm text-[#FFD6A5] leading-relaxed bg-[#140B04] p-3 border border-[#4A2400]">
              {finding.impact}
            </p>
          </div>

          {/* Section 3: Remediation */}
          <div className="space-y-1.5">
            <h3 className="text-[11px] font-bold text-primary uppercase tracking-widest flex items-center space-x-1.5">
              <span>[03] ACTIONABLE DEFENSIVE REMEDIATION</span>
            </h3>
            <div className="text-sm text-[#FFFCEB] leading-relaxed bg-[#161304] p-3.5 border-l-4 border-primary">
              {finding.remediation}
            </div>
          </div>

          {/* Section 4: Sanitized Evidence */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <h3 className="text-[11px] font-bold text-[#9EABB8] uppercase tracking-widest">
                [04] TELEMETRY EVIDENCE (SANITIZED // ZERO SECRET LEAKAGE)
              </h3>
              <button
                onClick={handleCopyEvidence}
                className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#141414] hover:bg-[#222] border border-border text-[10px] text-[#C7B988] transition cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-lime-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
            <pre className="p-3 bg-[#050505] border border-border text-[11px] text-[#A5F3FC] overflow-x-auto whitespace-pre-wrap word-break-all font-mono leading-relaxed max-h-40">
              {finding.evidence || 'No specific telemetry captured.'}
            </pre>
          </div>

          {/* Section 5: Standards & References */}
          {finding.references && finding.references.length > 0 && (
            <div className="space-y-1.5">
              <h3 className="text-[11px] font-bold text-[#7A7256] uppercase tracking-widest">
                [05] STANDARDS & EXTERNAL REFERENCES
              </h3>
              <ul className="space-y-1 text-xs">
                {finding.references.map((ref, idx) => (
                  <li key={idx}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center space-x-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      <span className="truncate">{ref}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Section 6: Related Findings */}
          {relatedFindings.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-border/80">
              <h3 className="text-[11px] font-bold text-[#A89F82] uppercase tracking-widest">
                [06] RELATED FINDINGS IN THIS AUDIT ({relatedFindings.length})
              </h3>
              <div className="space-y-1.5 max-h-36 overflow-y-auto">
                {relatedFindings.map(rf => (
                  <div key={rf.id} className="flex items-center justify-between p-2 bg-[#080808] border border-border text-[11px]">
                    <div className="flex items-center space-x-2 truncate">
                      <span className="text-[10px] font-bold text-primary">[{rf.severity}]</span>
                      <span className="text-[#FFF8DB] truncate">{rf.title}</span>
                    </div>
                    <span className="text-[10px] text-[#7A7256] ml-2 shrink-0">{rf.category}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer / Actions */}
        <div className="flex items-center justify-between px-6 py-3.5 bg-[#0D0D0D] border-t border-border">
          {onStatusChange ? (
            <button
              onClick={handleToggleAcceptedRisk}
              disabled={isUpdating}
              className={`px-3 py-1.5 border text-xs font-bold uppercase tracking-wider transition cursor-pointer ${
                status === 'ACCEPTED_RISK'
                  ? 'border-lime-500 bg-lime-950/40 text-lime-400 hover:bg-lime-900/60'
                  : 'border-amber-500/60 bg-amber-950/30 text-amber-400 hover:bg-amber-900/50'
              }`}
            >
              {isUpdating
                ? 'UPDATING...'
                : status === 'ACCEPTED_RISK'
                ? '[RE-OPEN AS ACTIVE ISSUE]'
                : '[MARK AS ACCEPTED RISK]'}
            </button>
          ) : <div />}

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-primary text-black text-xs font-bold uppercase tracking-wider hover:bg-[#FFE033] transition cursor-pointer"
          >
            [CLOSE INVESTIGATION]
          </button>
        </div>
      </div>
    </div>
  );
};
