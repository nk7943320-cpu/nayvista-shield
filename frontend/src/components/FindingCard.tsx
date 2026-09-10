import React, { useState } from 'react';
import { ChevronDown, ChevronUp, AlertOctagon, AlertTriangle, Info, CheckCircle2, ShieldAlert, Code2, Link as LinkIcon, Check } from 'lucide-react';
import { Finding, Severity } from '../types';

interface FindingCardProps {
  finding: Finding;
  index: number;
}

const severityBadgeStyles: Record<Severity, { bg: string; text: string; border: string; icon: any }> = {
  CRITICAL: { bg: 'bg-[#2B0B0B]', text: 'text-[#FF6666]', border: 'border-[#5C1414]', icon: AlertOctagon },
  HIGH: { bg: 'bg-[#2E1400]', text: 'text-[#FFA044]', border: 'border-[#5C2800]', icon: AlertTriangle },
  MEDIUM: { bg: 'bg-[#292200]', text: 'text-[#FFD400]', border: 'border-[#5C4D00]', icon: AlertTriangle },
  LOW: { bg: 'bg-[#102404]', text: 'text-[#84CC16]', border: 'border-[#254E0A]', icon: Info },
  INFO: { bg: 'bg-[#14171A]', text: 'text-[#9EABB8]', border: 'border-[#2B3036]', icon: CheckCircle2 },
};

export const FindingCard: React.FC<FindingCardProps> = ({ finding, index }) => {
  const [isOpen, setIsOpen] = useState(index < 2);
  const [copied, setCopied] = useState(false);
  const style = severityBadgeStyles[finding.severity] || severityBadgeStyles.INFO;
  const Icon = style.icon;

  const handleCopyEvidence = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="bg-[#0A0A0A] border border-border hover:border-primary/40 transition-colors shadow-sm font-mono">
      {/* Clickable Header */}
      <div
        onClick={() => setIsOpen(!isOpen)}
        className="p-4 sm:p-5 flex items-start sm:items-center justify-between cursor-pointer select-none gap-4"
      >
        <div className="flex items-start sm:items-center space-x-3.5 flex-1 min-w-0">
          <div className={`p-2 ${style.bg} ${style.border} border flex-shrink-0 mt-0.5 sm:mt-0`}>
            <Icon className={`w-4 h-4 ${style.text}`} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 border ${style.bg} ${style.text} ${style.border}`}>
                {finding.severity}
              </span>
              <span className="text-[10px] uppercase font-bold px-2 py-0.5 bg-[#141205] text-[#C7B988] border border-[#26200A]">
                CONFIDENCE: {finding.confidence}
              </span>
              <span className="text-[10px] font-medium px-2 py-0.5 bg-[#050505] text-primary border border-primary/30">
                {finding.owasp}
              </span>
            </div>
            <h3 className="text-sm sm:text-base font-bold text-[#FFF8DB] tracking-tight truncate">
              {finding.title}
            </h3>
            <p className="text-xs text-[#7A7256] truncate mt-0.5">
              &gt; {finding.url}
            </p>
          </div>
        </div>

        <button className="text-[#A89F82] hover:text-primary p-1 transition cursor-pointer">
          {isOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>
      </div>

      {/* Expanded Content Details */}
      {isOpen && (
        <div className="px-5 pb-5 pt-3 border-t border-border space-y-4 bg-[#050505] text-xs">
          {/* Description */}
          <div>
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary mb-1">
              [01] TECHNICAL CONTEXT & ROOT CAUSE
            </h4>
            <p className="text-[#D4C9A8] leading-relaxed">
              {finding.description}
            </p>
          </div>

          {/* Impact */}
          <div>
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-[#FFA044] mb-1 flex items-center space-x-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-[#FFA044]" />
              <span>[02] SECURITY IMPACT & RISK EXPOSURE</span>
            </h4>
            <p className="text-[#D4C9A8] leading-relaxed">
              {finding.impact}
            </p>
          </div>

          {/* Evidence box */}
          {finding.evidence && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary flex items-center space-x-1.5">
                  <Code2 className="w-3.5 h-3.5 text-primary" />
                  <span>[03] SANITIZED OBSERVED EVIDENCE</span>
                </h4>
                <button
                  onClick={handleCopyEvidence}
                  className="text-[10px] text-[#A89F82] hover:text-primary transition flex items-center space-x-1 cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-lime-400" />
                      <span className="text-lime-400">COPIED</span>
                    </>
                  ) : (
                    <span>[COPY RAW]</span>
                  )}
                </button>
              </div>
              <div className="bg-[#000000] border border-border p-3 text-[11px] text-[#E6DCB8] overflow-x-auto whitespace-pre-wrap word-break-all select-all">
                {finding.evidence}
              </div>
            </div>
          )}

          {/* Affected URLs if multiple */}
          {finding.affected_urls && finding.affected_urls.length > 1 && (
            <div>
              <h4 className="text-[10px] font-bold uppercase tracking-wider text-[#A89F82] mb-1 flex items-center space-x-1.5">
                <LinkIcon className="w-3.5 h-3.5 text-[#A89F82]" />
                <span>[04] OBSERVED ON {finding.affected_urls.length} ENDPOINTS</span>
              </h4>
              <ul className="space-y-1 text-[11px] text-[#7A7256] max-h-24 overflow-y-auto pl-2 border-l border-border">
                {finding.affected_urls.map((u, i) => (
                  <li key={i} className="truncate">&bull; {u}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Remediation box */}
          <div className="bg-[#121004] border-l-3 border-primary p-3.5">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary mb-1">
              [05] ACTIONABLE REMEDIATION GUIDANCE
            </h4>
            <p className="text-[#FFF8DB] leading-relaxed">
              {finding.remediation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
