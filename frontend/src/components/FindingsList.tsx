import React, { useState, useMemo } from 'react';
import { Search, ShieldCheck, LayoutList, Table as TableIcon, ChevronDown, ChevronUp, Code2, ShieldAlert, Check, Link as LinkIcon, AlertOctagon, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
import { Finding, Severity } from '../types';
import { FindingCard } from './FindingCard';

interface FindingsListProps {
  findings: Finding[];
  onOpenFindingDetail?: (finding: Finding) => void;
}

const severityBadgeStyles: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-[#2B0B0B]', text: 'text-[#FF6666]', border: 'border-[#5C1414]' },
  HIGH: { bg: 'bg-[#2E1400]', text: 'text-[#FFA044]', border: 'border-[#5C2800]' },
  MEDIUM: { bg: 'bg-[#292200]', text: 'text-[#FFD400]', border: 'border-[#5C4D00]' },
  LOW: { bg: 'bg-[#102404]', text: 'text-[#84CC16]', border: 'border-[#254E0A]' },
  INFO: { bg: 'bg-[#14171A]', text: 'text-[#9EABB8]', border: 'border-[#2B3036]' },
};

export const FindingsList: React.FC<FindingsListProps> = ({ findings, onOpenFindingDetail }) => {
  const [viewMode, setViewMode] = useState<'table' | 'cards'>('table');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [expandedRowId, setExpandedRowId] = useState<string | null>(null);
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);

  const categories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach(f => {
      if (f.category) set.add(f.category);
    });
    return Array.from(set).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesSearch =
        searchQuery === '' ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.url.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesSeverity =
        selectedSeverity === 'ALL' || f.severity === selectedSeverity;

      const matchesCategory =
        selectedCategory === 'ALL' || f.category === selectedCategory;

      return matchesSearch && matchesSeverity && matchesCategory;
    });
  }, [findings, searchQuery, selectedSeverity, selectedCategory]);

  const counts = useMemo(() => {
    return {
      ALL: findings.length,
      CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
      HIGH: findings.filter(f => f.severity === 'HIGH').length,
      MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
      LOW: findings.filter(f => f.severity === 'LOW').length,
      INFO: findings.filter(f => f.severity === 'INFO').length,
    };
  }, [findings]);

  const toggleRowExpand = (id: string) => {
    setExpandedRowId(prev => (prev === id ? null : id));
  };

  const handleCopyEvidence = (id: string, evidence: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(evidence);
    setCopiedEvidenceId(id);
    setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  return (
    <div className="space-y-4 font-mono">
      {/* Controls Bar */}
      <div className="bg-[#0A0A0A] border border-border p-4 space-y-3.5">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute left-3 top-2.5 text-primary text-xs font-bold">&gt;</div>
            <input
              type="text"
              placeholder="Search findings by keyword, URL, or CWE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-4 py-2 bg-[#030303] border border-border text-xs text-[#FFF8DB] placeholder-[#5A523A] focus:border-primary focus:outline-none tracking-wide"
            />
          </div>

          <div className="sm:w-72">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-3 py-2 bg-[#030303] border border-border text-xs text-[#C7B988] focus:border-primary focus:outline-none tracking-wide"
            >
              <option value="ALL">ALL OWASP CATEGORIES</option>
              {categories.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex flex-wrap gap-2 pt-2 border-t border-border">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => {
            const count = counts[sev];
            const isSelected = selectedSeverity === sev;

            let pillStyle = 'bg-[#050505] text-[#A89F82] border-border hover:border-primary/40';
            if (isSelected) {
              if (sev === 'CRITICAL') pillStyle = 'bg-[#2B0B0B] text-[#FF6666] border-[#5C1414] font-bold';
              else if (sev === 'HIGH') pillStyle = 'bg-[#2E1400] text-[#FFA044] border-[#5C2800] font-bold';
              else if (sev === 'MEDIUM') pillStyle = 'bg-[#292200] text-primary border-primary font-bold';
              else if (sev === 'LOW') pillStyle = 'bg-[#102404] text-[#84CC16] border-[#254E0A] font-bold';
              else if (sev === 'INFO') pillStyle = 'bg-[#14171A] text-[#9EABB8] border-[#2B3036] font-bold';
              else pillStyle = 'bg-primary/10 text-primary border-primary font-bold glow-yellow-sm';
            }

            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-3 py-1 text-xs uppercase tracking-wider border transition flex items-center space-x-1.5 cursor-pointer ${pillStyle}`}
              >
                <span>{sev === 'ALL' ? 'ALL' : sev}</span>
                <span className="text-[10px] px-1 py-0.2 bg-black/60 text-[#FFF8DB] font-bold">
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Results Sub-header with View Switcher */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 text-xs text-[#7A7256] px-1">
        <div className="flex items-center space-x-3">
          <span>SHOWING [ {filteredFindings.length} / {findings.length} ] AUDITED FINDINGS</span>
          {(selectedSeverity !== 'ALL' || selectedCategory !== 'ALL' || searchQuery) && (
            <button
              onClick={() => { setSelectedSeverity('ALL'); setSelectedCategory('ALL'); setSearchQuery(''); }}
              className="text-primary hover:underline cursor-pointer text-[11px]"
            >
              [RESET FILTERS]
            </button>
          )}
        </div>

        {/* View mode toggle */}
        <div className="flex items-center space-x-1 border border-border bg-[#050505] p-0.5">
          <button
            onClick={() => setViewMode('table')}
            className={`flex items-center space-x-1 px-2.5 py-1 text-[11px] tracking-wider uppercase transition cursor-pointer ${
              viewMode === 'table'
                ? 'bg-primary text-black font-bold'
                : 'text-[#A89F82] hover:text-[#FFF8DB]'
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            <span>TABLE</span>
          </button>
          <button
            onClick={() => setViewMode('cards')}
            className={`flex items-center space-x-1 px-2.5 py-1 text-[11px] tracking-wider uppercase transition cursor-pointer ${
              viewMode === 'cards'
                ? 'bg-primary text-black font-bold'
                : 'text-[#A89F82] hover:text-[#FFF8DB]'
            }`}
          >
            <LayoutList className="w-3.5 h-3.5" />
            <span>CARDS</span>
          </button>
        </div>
      </div>

      {/* Findings Content */}
      {filteredFindings.length > 0 ? (
        viewMode === 'table' ? (
          /* Table View */
          <div className="bg-[#0A0A0A] border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border bg-[#050505] text-[#A89F82] text-[10px] uppercase tracking-wider">
                    <th className="py-2.5 px-3 w-10 text-center">#</th>
                    <th className="py-2.5 px-3 w-28">SEVERITY</th>
                    <th className="py-2.5 px-3">FINDING TITLE</th>
                    <th className="py-2.5 px-3 hidden md:table-cell">OWASP CATEGORY</th>
                    <th className="py-2.5 px-3 hidden lg:table-cell">TARGET PATH</th>
                    <th className="py-2.5 px-3 w-24 text-center hidden sm:table-cell">CONFIDENCE</th>
                    <th className="py-2.5 px-3 w-20 text-center">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredFindings.map((finding, index) => {
                    const rowId = finding.id || `f-${index}`;
                    const isExpanded = expandedRowId === rowId;
                    const style = severityBadgeStyles[finding.severity] || severityBadgeStyles.INFO;

                    let pathDisplay = finding.url;
                    try {
                      const parsed = new URL(finding.url);
                      pathDisplay = parsed.pathname + (parsed.search || '');
                    } catch {}

                    return (
                      <React.Fragment key={rowId}>
                        <tr
                          onClick={() => toggleRowExpand(rowId)}
                          className={`hover:bg-[#121005] cursor-pointer transition-colors ${
                            isExpanded ? 'bg-[#121005]' : ''
                          }`}
                        >
                          <td className="py-3 px-3 text-center text-[#5A523A] font-bold">
                            {index + 1}
                          </td>
                          <td className="py-3 px-3">
                            <span className={`text-[10px] font-bold uppercase px-2 py-0.5 border inline-block ${style.bg} ${style.text} ${style.border}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-bold text-[#FFF8DB]">
                            <div className="flex items-center space-x-2">
                              <span>{finding.title}</span>
                              {finding.status === 'ACCEPTED_RISK' && (
                                <span className="px-1.5 py-0.2 text-[9px] bg-amber-950/60 border border-amber-500/60 text-amber-300 font-bold">
                                  [ACCEPTED RISK]
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-[#7A7256] truncate max-w-xs mt-0.5">
                              {finding.cwe && <span className="text-primary mr-1.5 font-mono">[{finding.cwe}]</span>}
                              {finding.affected_component && <span className="text-[#A89F82] mr-1.5 font-mono">{finding.affected_component} &bull;</span>}
                              {pathDisplay}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-[#C7B988] hidden md:table-cell text-[11px]">
                            {finding.owasp || finding.category}
                          </td>
                          <td className="py-3 px-3 text-[#7A7256] hidden lg:table-cell truncate max-w-[200px] text-[11px]">
                            {pathDisplay}
                          </td>
                          <td className="py-3 px-3 text-center text-[#A89F82] text-[10px] hidden sm:table-cell">
                            {finding.confidence}
                          </td>
                          <td className="py-3 px-3 text-center">
                            <div className="flex items-center justify-center space-x-1">
                              {onOpenFindingDetail && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onOpenFindingDetail(finding);
                                  }}
                                  className="text-[#FFF8DB] bg-[#141414] hover:bg-primary hover:text-black border border-border text-[10px] font-bold px-1.5 py-0.5 transition cursor-pointer"
                                  title="Open deep investigation modal"
                                >
                                  [DETAIL]
                                </button>
                              )}
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleRowExpand(rowId);
                                }}
                                className="text-primary hover:text-primary-bright p-1 text-[11px] font-bold cursor-pointer inline-flex items-center space-x-0.5"
                              >
                                <span>{isExpanded ? '[HIDE]' : '[INSPECT]'}</span>
                                {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              </button>
                            </div>
                          </td>
                        </tr>

                        {/* Inline Expanded Investigation Card */}
                        {isExpanded && (
                          <tr className="bg-[#050505]">
                            <td colSpan={7} className="p-4 sm:p-5 border-t border-border">
                              <div className="space-y-3.5 text-xs">
                                {/* Details Header */}
                                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/70 pb-2">
                                  <div className="text-primary text-[11px] font-bold uppercase tracking-wider">
                                    INVESTIGATION REPORT: {finding.title}
                                  </div>
                                  <div className="text-[#A89F82] text-[11px]">
                                    ENDPOINT: <span className="text-[#FFF8DB]">{finding.url}</span>
                                  </div>
                                </div>

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

                                {/* Evidence */}
                                {finding.evidence && (
                                  <div>
                                    <div className="flex items-center justify-between mb-1.5">
                                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary flex items-center space-x-1.5">
                                        <Code2 className="w-3.5 h-3.5 text-primary" />
                                        <span>[03] SANITIZED OBSERVED EVIDENCE</span>
                                      </h4>
                                      <button
                                        onClick={(e) => handleCopyEvidence(rowId, finding.evidence || '', e)}
                                        className="text-[10px] text-[#A89F82] hover:text-primary transition flex items-center space-x-1 cursor-pointer"
                                      >
                                        {copiedEvidenceId === rowId ? (
                                          <>
                                            <Check className="w-3 h-3 text-lime-400" />
                                            <span className="text-lime-400">COPIED</span>
                                          </>
                                        ) : (
                                          <span>[COPY RAW]</span>
                                        )}
                                      </button>
                                    </div>
                                    <div className="bg-[#000000] border border-border p-3 text-[11px] text-[#E6DCB8] overflow-x-auto whitespace-pre-wrap break-all select-all">
                                      {finding.evidence}
                                    </div>
                                  </div>
                                )}

                                {/* Structured Validation Evidence */}
                                {finding.structured_evidence && (
                                  <div className="bg-[#080808] border border-primary/40 p-3 space-y-1.5 text-[11px] font-mono">
                                    <div className="text-[10px] font-bold text-primary uppercase tracking-wider">
                                      [AUDITOR EVIDENCE SPECIFICATION]
                                    </div>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[#C7B988]">
                                      <div><span className="text-[#7A7256]">TEST:</span> {finding.structured_evidence.test}</div>
                                      <div><span className="text-[#7A7256]">CONFIDENCE:</span> <span className="text-primary font-bold">{finding.structured_evidence.confidence}</span></div>
                                      <div><span className="text-[#7A7256]">EXPECTED:</span> {finding.structured_evidence.expected}</div>
                                      <div><span className="text-[#7A7256]">OBSERVED:</span> {finding.structured_evidence.observed}</div>
                                    </div>
                                  </div>
                                )}

                                {/* Affected URLs */}
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

                                {/* Remediation */}
                                <div className="bg-[#121004] border-l-3 border-primary p-3.5">
                                  <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary mb-1">
                                    [05] ACTIONABLE REMEDIATION GUIDANCE
                                  </h4>
                                  <p className="text-[#FFF8DB] leading-relaxed">
                                    {finding.remediation}
                                  </p>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          /* Cards View */
          <div className="space-y-3">
            {filteredFindings.map((finding, index) => (
              <FindingCard key={finding.id || index} finding={finding} index={index} />
            ))}
          </div>
        )
      ) : findings.length === 0 ? (
        <div className="bg-[#0A0A0A] border-2 border-lime-500/40 p-12 text-center text-[#7A7256]">
          <ShieldCheck className="w-12 h-12 text-lime-400 mx-auto mb-3" />
          <p className="text-sm font-bold text-lime-400 uppercase tracking-wider">ZERO VULNERABILITIES OR DEFECTS DISCOVERED</p>
          <p className="text-xs text-[#C7B988] mt-1.5 max-w-md mx-auto">
            All evaluated same-origin endpoints passed defensive checks for security headers, cookie flags, CORS policies, and sensitive disclosures.
          </p>
        </div>
      ) : (
        <div className="bg-[#0A0A0A] border border-border p-12 text-center text-[#7A7256]">
          <ShieldCheck className="w-10 h-10 text-[#4A4535] mx-auto mb-3" />
          <p className="text-sm font-bold text-[#C7B988] uppercase tracking-wider">NO FINDINGS MATCH THE APPLIED FILTERS</p>
          <p className="text-xs text-[#7A7256] mt-1">Try resetting filter options or query keywords.</p>
        </div>
      )}
    </div>
  );
};

