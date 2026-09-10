import React, { useState, useEffect } from 'react';
import {
  Terminal,
  ArrowRight,
  FileText,
  GitCompare,
  Trash2,
  AlertTriangle,
  Globe,
  TrendingUp,
  Layers,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { ScanRecord, TargetHistoryGroup } from '../types';
import { deleteScan, getTargetHistory, getReportDownloadUrl } from '../api';

interface ScanHistoryProps {
  scans: ScanRecord[];
  onSelectScan: (scanId: string) => void;
  onNewScan: () => void;
  onOpenReport: (scan: ScanRecord) => void;
  onCompareScans: (scanA: string, scanB: string) => void;
  onRefreshHistory: () => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  scans,
  onSelectScan,
  onNewScan,
  onOpenReport,
  onCompareScans,
  onRefreshHistory,
}) => {
  const [viewMode, setViewMode] = useState<'all' | 'targets'>('all');
  const [targetGroups, setTargetGroups] = useState<TargetHistoryGroup[]>([]);
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);

  // Compare selection state
  const [compareBaseId, setCompareBaseId] = useState<string | null>(null);

  // Delete confirmation state
  const [scanToDelete, setScanToDelete] = useState<ScanRecord | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    loadTargetHistory();
  }, [scans]);

  const loadTargetHistory = async () => {
    try {
      const groups = await getTargetHistory();
      setTargetGroups(groups);
    } catch {
      // Ignore if server unreachable
    }
  };

  const handleStartCompare = (scanId: string) => {
    if (compareBaseId === scanId) {
      setCompareBaseId(null);
    } else if (!compareBaseId) {
      setCompareBaseId(scanId);
    } else {
      onCompareScans(compareBaseId, scanId);
      setCompareBaseId(null);
    }
  };

  const handleConfirmDelete = async () => {
    if (!scanToDelete) return;
    setIsDeleting(true);
    try {
      await deleteScan(scanToDelete.id);
      setScanToDelete(null);
      onRefreshHistory();
    } catch (err) {
      console.error('Delete failed:', err);
    } finally {
      setIsDeleting(false);
    }
  };

  const toggleTargetExpand = (target: string) => {
    setExpandedTarget(prev => (prev === target ? null : target));
  };

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-6 font-mono text-xs">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-widest mb-1">
            <Terminal className="w-3.5 h-3.5" />
            <span>AUDIT INTELLIGENCE // HISTORICAL REPOSITORY</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#FFF8DB] tracking-wide">
            Persistent Security Records & Trends
          </h2>
          <p className="text-xs text-[#A89F82] mt-0.5">
            Defensive assessments, target evolution metrics, and historical compliance records.
          </p>
        </div>

        <div className="flex items-center space-x-2 self-start sm:self-center">
          <button
            onClick={() => setViewMode(viewMode === 'all' ? 'targets' : 'all')}
            className="px-3 py-1.5 bg-[#121212] hover:bg-[#1A1A1A] text-primary border border-primary/50 text-xs font-bold uppercase tracking-wider transition cursor-pointer"
          >
            {viewMode === 'all' ? '[GROUP BY TARGET]' : '[ALL SCANS LIST]'}
          </button>

          <button
            onClick={onNewScan}
            className="px-4 py-1.5 bg-primary text-black border border-primary text-xs font-bold uppercase tracking-wider hover:bg-[#FFE033] transition cursor-pointer shadow-[0_0_12px_rgba(255,212,0,0.2)]"
          >
            [NEW ASSESSMENT]
          </button>
        </div>
      </div>

      {/* Compare Notice Banner if Base Selected */}
      {compareBaseId && (
        <div className="p-3 bg-[#181504] border-2 border-primary text-primary flex items-center justify-between animate-pulse">
          <div className="flex items-center space-x-2">
            <GitCompare className="w-4 h-4" />
            <span>
              SELECT A SECOND SCAN TO COMPARE AGAINST <strong>#{compareBaseId.slice(0, 8)}</strong>
            </span>
          </div>
          <button
            onClick={() => setCompareBaseId(null)}
            className="px-2 py-0.5 bg-[#000] text-primary border border-primary text-[10px] uppercase font-bold cursor-pointer"
          >
            [CANCEL]
          </button>
        </div>
      )}

      {/* View Mode: Group by Target */}
      {viewMode === 'targets' ? (
        <div className="space-y-4">
          <div className="text-[11px] text-[#A89F82] uppercase tracking-wider font-bold">
            HISTORICAL DRIFT GROUPED BY NORMALIZED TARGET ORIGIN ({targetGroups.length} TARGETS)
          </div>

          {targetGroups.length === 0 ? (
            <div className="p-8 text-center text-[#7A7256] bg-[#0A0A0A] border border-border">
              No historical targets recorded yet.
            </div>
          ) : (
            <div className="space-y-3">
              {targetGroups.map(group => {
                const isExpanded = expandedTarget === group.normalized_target;

                return (
                  <div key={group.normalized_target} className="bg-[#0A0A0A] border border-border overflow-hidden">
                    <div
                      onClick={() => toggleTargetExpand(group.normalized_target)}
                      className="p-4 bg-[#0F0F0F] hover:bg-[#141414] cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/60 transition"
                    >
                      <div className="flex items-center space-x-3">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-primary" /> : <ChevronRight className="w-4 h-4 text-[#7A7256]" />}
                        <Globe className="w-4 h-4 text-primary" />
                        <div>
                          <div className="text-sm font-bold text-[#FFF8DB]">{group.target_hostname}</div>
                          <div className="text-[10px] text-[#7A7256] truncate max-w-sm">&gt; {group.normalized_target}</div>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-3">
                        <span className="px-2 py-0.5 bg-[#050505] border border-border text-[11px] text-[#A89F82]">
                          {group.scan_count} ASSESSMENTS
                        </span>
                        <div className="flex items-center space-x-1.5">
                          <span className="text-base font-extrabold text-primary">{group.latest_score}</span>
                          <span className="text-[10px] px-1 py-0.2 border border-border bg-[#050505] font-bold">
                            GRADE {group.latest_grade}
                          </span>
                        </div>
                        <span className="text-[10px] text-lime-400 font-bold uppercase">
                          [{group.latest_posture}]
                        </span>
                      </div>
                    </div>

                    {/* Expanded Scans List for Target */}
                    {isExpanded && (
                      <div className="p-3 bg-[#050505] divide-y divide-border/60">
                        {group.scans.map((s, idx) => (
                          <div key={s.id} className="py-2.5 px-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-[#0A0A0A] transition">
                            <div className="flex items-center space-x-3">
                              <span className="text-[10px] text-[#7A7256]">#{group.scans.length - idx}</span>
                              <span className="text-[#FFF8DB] font-bold">{s.id.slice(0, 8)}</span>
                              <span className="text-[11px] text-[#7A7256]">{new Date(s.started_at).toISOString().replace('T', ' ').slice(0, 16)} UTC</span>
                            </div>

                            <div className="flex items-center space-x-3">
                              <span className="text-xs font-bold text-primary">{s.security_score !== null && s.security_score !== undefined ? `${s.security_score} PTS` : 'N/A'}</span>
                              <span className="text-[10px] px-1.5 py-0.2 border border-border bg-[#080808]">GRADE {s.grade || 'N/A'}</span>
                              <span className="text-[10px] text-[#A89F82]">{s.findings_count} FINDINGS</span>

                              <button
                                onClick={() => onSelectScan(s.id)}
                                className="px-2 py-0.5 bg-[#141414] hover:bg-primary hover:text-black border border-border text-[10px] font-bold uppercase transition cursor-pointer"
                              >
                                [INSPECT]
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : (
        /* Flat Scans Table */
        <div className="bg-[#0A0A0A] border border-border overflow-hidden shadow-sm">
          {scans && scans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#030303] text-[10px] font-bold text-[#A89F82] uppercase tracking-widest border-b border-border">
                  <tr>
                    <th className="px-4 py-3">TARGET HOSTNAME</th>
                    <th className="px-4 py-3 hidden md:table-cell">MODE / IP</th>
                    <th className="px-4 py-3">SCORE & GRADE</th>
                    <th className="px-4 py-3">POSTURE</th>
                    <th className="px-4 py-3">FINDINGS</th>
                    <th className="px-4 py-3 hidden md:table-cell">DURATION</th>
                    <th className="px-4 py-3 hidden sm:table-cell">TIMESTAMP (UTC)</th>
                    <th className="px-4 py-3 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-[#C7B988]">
                  {scans.map((scan) => {
                    const hasScore = scan.security_score !== null && scan.security_score !== undefined;
                    const scoreColor = !hasScore
                      ? 'text-primary'
                      : scan.security_score! >= 80
                      ? 'text-[#84CC16]'
                      : scan.security_score! >= 60
                      ? 'text-primary'
                      : 'text-[#FF4444]';

                    const isBase = compareBaseId === scan.id;

                    return (
                      <tr key={scan.id} className={`hover:bg-[#121212] transition ${isBase ? 'bg-[#1F1A05] border-l-4 border-primary' : ''}`}>
                        <td className="px-4 py-3 font-bold text-[#FFF8DB]">
                          <div className="text-xs">{scan.target_hostname}</div>
                          <div className="text-[10px] text-[#7A7256] truncate max-w-xs">&gt; {scan.target_url}</div>
                        </td>

                        <td className="px-4 py-3 hidden md:table-cell">
                          <div className="text-[10px] text-[#38D39F] font-bold">{scan.mode || 'DEFENSIVE / SAFE'}</div>
                          <div className="text-[10px] text-[#7A7256] font-mono">{scan.resolved_ip || 'N/A'}</div>
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex items-center space-x-2">
                            <span className={`text-sm font-extrabold ${scoreColor}`}>
                              {hasScore ? scan.security_score : 'N/A'}
                            </span>
                            <span className="text-[10px] px-1.5 py-0.2 border border-border bg-[#050505] font-bold text-[#A89F82]">
                              {scan.grade || 'N/A'}
                            </span>
                          </div>
                        </td>

                        <td className="px-4 py-3">
                          <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 border ${
                            scan.posture === 'LIMITED' ? 'bg-[#211A05] text-[#FFD400] border-[#8C7300]' :
                            scan.posture === 'RESTRICTED' ? 'bg-[#292200] text-[#FFD400] border-[#5C4D00]' :
                            scan.posture === 'DEGRADED' ? 'bg-[#2B0B0B] text-[#FF6666] border-[#5C1414]' :
                            'bg-[#102404] text-[#84CC16] border-[#254E0A]'
                          }`}>
                            {scan.posture || 'ASSESSED'}
                          </span>
                        </td>

                        <td className="px-4 py-3 text-xs font-bold text-[#FFF8DB]">
                          {(scan.findings || []).length}
                        </td>

                        <td className="px-4 py-3 text-xs text-[#A89F82] hidden md:table-cell">
                          {scan.duration_seconds ? `${scan.duration_seconds}s` : '-'}
                        </td>

                        <td className="px-4 py-3 text-[11px] text-[#7A7256] whitespace-nowrap hidden sm:table-cell">
                          {new Date(scan.started_at).toISOString().replace('T', ' ').slice(0, 16)}
                        </td>

                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end space-x-1.5">
                            {/* Inspect */}
                            <button
                              onClick={() => onSelectScan(scan.id)}
                              className="px-2 py-1 bg-[#121212] hover:bg-[#1C1805] text-primary border border-border text-[10px] font-bold uppercase transition cursor-pointer"
                              title="Inspect audit results"
                            >
                              [INSPECT]
                            </button>

                            {/* Report */}
                            <button
                              onClick={() => onOpenReport(scan)}
                              className="p-1 text-[#A89F82] hover:text-primary hover:bg-[#141414] border border-transparent hover:border-border transition cursor-pointer"
                              title="Open audit report"
                            >
                              <FileText className="w-3.5 h-3.5" />
                            </button>

                            {/* Compare */}
                            <button
                              onClick={() => handleStartCompare(scan.id)}
                              className={`p-1 border transition cursor-pointer ${
                                isBase
                                  ? 'bg-primary text-black border-primary'
                                  : 'text-[#A89F82] hover:text-[#FFA044] hover:bg-[#141414] border-transparent hover:border-border'
                              }`}
                              title={isBase ? 'Selected as comparison base' : 'Compare with another scan'}
                            >
                              <GitCompare className="w-3.5 h-3.5" />
                            </button>

                            {/* Delete */}
                            <button
                              onClick={() => setScanToDelete(scan)}
                              className="p-1 text-[#7A7256] hover:text-[#FF4444] hover:bg-[#1F0A0A] border border-transparent hover:border-[#5C1414] transition cursor-pointer"
                              title="Delete audit record"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center text-[#7A7256]">
              No historical security audits found.
            </div>
          )}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {scanToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
          <div className="w-full max-w-md bg-[#0A0A0A] border-2 border-[#FF4444] p-5 space-y-4 shadow-[0_0_25px_rgba(255,68,68,0.25)]">
            <div className="flex items-center space-x-2 text-[#FF4444] font-bold text-sm uppercase">
              <AlertTriangle className="w-4 h-4" />
              <span>CONFIRM DESTRUCTIVE ACTION</span>
            </div>
            <p className="text-xs text-[#C7B988] leading-relaxed">
              Are you sure you want to permanently delete audit record{' '}
              <strong className="text-[#FFF8DB]">#{scanToDelete.id.slice(0, 8)}</strong> for target{' '}
              <strong className="text-[#FFF8DB]">{scanToDelete.target_hostname}</strong>?
            </p>
            <p className="text-[11px] text-[#7A7256]">
              This action cannot be undone. Associated findings and report caches will be purged.
            </p>
            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                onClick={() => setScanToDelete(null)}
                disabled={isDeleting}
                className="px-3 py-1.5 bg-[#141414] hover:bg-[#222] border border-border text-xs text-[#A89F82] font-bold uppercase transition cursor-pointer"
              >
                [CANCEL]
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-1.5 bg-[#FF4444] text-black text-xs font-bold uppercase tracking-wider hover:bg-[#FF6666] transition cursor-pointer"
              >
                {isDeleting ? 'DELETING...' : '[CONFIRM PERMANENT DELETION]'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
