import React, { useState } from 'react';
import { X, ArrowRight, ShieldCheck, Plus, Minus, Equal, RotateCw, AlertTriangle, Shield } from 'lucide-react';
import { ScanComparison, Finding } from '../types';

interface ScanComparisonModalProps {
  comparison: ScanComparison;
  onClose: () => void;
}

export const ScanComparisonModal: React.FC<ScanComparisonModalProps> = ({ comparison, onClose }) => {
  const [activeTab, setActiveTab] = useState<'all' | 'new' | 'resolved' | 'persistent' | 'regressed'>('all');

  const { base_scan, target_scan, delta, findings, summary } = comparison;

  const scoreDiffColor =
    delta.score > 0 ? 'text-[#84CC16]' : delta.score < 0 ? 'text-[#FF4444]' : 'text-primary';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm font-mono animate-in fade-in duration-150">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-[#0A0A0A] border-2 border-primary flex flex-col shadow-[0_0_35px_rgba(255,212,0,0.3)]">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between px-5 py-3.5 bg-[#121004] border-b border-primary/40">
          <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-wider">
            <Shield className="w-4 h-4" />
            <span>AUDIT COMPARISON // {base_scan.target_hostname}</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-[#A89F82] hover:text-primary hover:bg-[#1E1B0A] transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-[#C7B988]">
          {/* Comparison Header Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Base Scan */}
            <div className="bg-[#0D0D0D] border border-border p-3.5">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">BASE AUDIT (EARLIER)</div>
              <div className="text-sm font-bold text-[#FFF8DB] mt-1 truncate">
                {new Date(base_scan.started_at).toISOString().slice(0, 10)} &bull; {base_scan.id.slice(0, 8)}
              </div>
              <div className="mt-2 flex items-center space-x-3">
                <span className="text-xl font-extrabold text-[#FFF8DB]">
                  {base_scan.security_score !== null && base_scan.security_score !== undefined ? base_scan.security_score : 'N/A'}
                </span>
                <span className="text-[10px] px-1.5 py-0.5 border border-border bg-[#050505]">GRADE {base_scan.grade || 'N/A'}</span>
                <span className="text-[10px] text-[#7A7256]">[{base_scan.posture || 'ASSESSED'}]</span>
              </div>
            </div>

            {/* Target Scan */}
            <div className="bg-[#0D0D0D] border border-border p-3.5">
              <div className="text-[10px] text-[#7A7256] uppercase font-bold">TARGET AUDIT (LATER)</div>
              <div className="text-sm font-bold text-[#FFF8DB] mt-1 truncate">
                {new Date(target_scan.started_at).toISOString().slice(0, 10)} &bull; {target_scan.id.slice(0, 8)}
              </div>
              <div className="mt-2 flex items-center space-x-3">
                <span className="text-xl font-extrabold text-[#FFF8DB]">
                  {target_scan.security_score !== null && target_scan.security_score !== undefined ? target_scan.security_score : 'N/A'}
                </span>
                <span className="text-[10px] px-1.5 py-0.5 border border-border bg-[#050505]">GRADE {target_scan.grade || 'N/A'}</span>
                <span className="text-[10px] text-[#7A7256]">[{target_scan.posture || 'ASSESSED'}]</span>
              </div>
            </div>

            {/* Shift Summary */}
            <div className="bg-[#141205] border border-primary/40 p-3.5 flex flex-col justify-between">
              <div className="text-[10px] text-primary uppercase font-bold">CALIBRATED DELTA</div>
              <div className="flex items-center space-x-2 mt-1">
                <span className={`text-2xl font-black ${scoreDiffColor}`}>
                  {delta.score > 0 ? `+${delta.score}` : delta.score}
                </span>
                <span className="text-xs text-[#A89F82]">PTS SHIFT</span>
              </div>
              <div className="text-[11px] text-[#C7B988] mt-1">
                Grade: {base_scan.grade} &rarr; <strong className="text-[#FFF8DB]">{target_scan.grade}</strong>
                {delta.risk_changed && (
                  <span className="ml-2 text-amber-400">Risk: {target_scan.risk_level}</span>
                )}
              </div>
            </div>
          </div>

          {/* Finding Counts Shift Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <button
              onClick={() => setActiveTab('new')}
              className={`p-3 border text-left cursor-pointer transition ${
                activeTab === 'new' ? 'border-[#FFA044] bg-[#2E1400]' : 'border-border bg-[#080808] hover:border-[#FFA044]/50'
              }`}
            >
              <div className="flex items-center space-x-1.5 text-[#FFA044] font-bold text-[11px]">
                <Plus className="w-3.5 h-3.5" />
                <span>NEW FINDINGS</span>
              </div>
              <div className="text-xl font-bold text-[#FFF8DB] mt-1">+{summary.new_count}</div>
            </button>

            <button
              onClick={() => setActiveTab('resolved')}
              className={`p-3 border text-left cursor-pointer transition ${
                activeTab === 'resolved' ? 'border-[#84CC16] bg-[#102404]' : 'border-border bg-[#080808] hover:border-[#84CC16]/50'
              }`}
            >
              <div className="flex items-center space-x-1.5 text-[#84CC16] font-bold text-[11px]">
                <Minus className="w-3.5 h-3.5" />
                <span>RESOLVED FINDINGS</span>
              </div>
              <div className="text-xl font-bold text-[#FFF8DB] mt-1">-{summary.resolved_count}</div>
            </button>

            <button
              onClick={() => setActiveTab('persistent')}
              className={`p-3 border text-left cursor-pointer transition ${
                activeTab === 'persistent' ? 'border-primary bg-[#292200]' : 'border-border bg-[#080808] hover:border-primary/50'
              }`}
            >
              <div className="flex items-center space-x-1.5 text-primary font-bold text-[11px]">
                <Equal className="w-3.5 h-3.5" />
                <span>PERSISTENT ISSUES</span>
              </div>
              <div className="text-xl font-bold text-[#FFF8DB] mt-1">={summary.persistent_count}</div>
            </button>

            <button
              onClick={() => setActiveTab('regressed')}
              className={`p-3 border text-left cursor-pointer transition ${
                activeTab === 'regressed' ? 'border-[#FF6666] bg-[#2B0B0B]' : 'border-border bg-[#080808] hover:border-[#FF6666]/50'
              }`}
            >
              <div className="flex items-center space-x-1.5 text-[#FF6666] font-bold text-[11px]">
                <RotateCw className="w-3.5 h-3.5" />
                <span>REGRESSED / RECURRED</span>
              </div>
              <div className="text-xl font-bold text-[#FFF8DB] mt-1">&circlearrowright;{summary.regressed_count}</div>
            </button>
          </div>

          {/* Attack Surface Changes */}
          <div className="bg-[#0D0D0D] border border-border p-3.5">
            <div className="text-[10px] text-[#7A7256] uppercase font-bold mb-2">ATTACK SURFACE DRIFT</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div>
                Pages: <strong className="text-[#FFF8DB]">{delta.attack_surface_diff.pages >= 0 ? `+${delta.attack_surface_diff.pages}` : delta.attack_surface_diff.pages}</strong>
              </div>
              <div>
                Endpoints: <strong className="text-[#FFF8DB]">{delta.attack_surface_diff.endpoints >= 0 ? `+${delta.attack_surface_diff.endpoints}` : delta.attack_surface_diff.endpoints}</strong>
              </div>
              <div>
                Forms: <strong className="text-[#FFF8DB]">{delta.attack_surface_diff.forms >= 0 ? `+${delta.attack_surface_diff.forms}` : delta.attack_surface_diff.forms}</strong>
              </div>
              <div>
                Parameters: <strong className="text-[#FFF8DB]">{delta.attack_surface_diff.parameters >= 0 ? `+${delta.attack_surface_diff.parameters}` : delta.attack_surface_diff.parameters}</strong>
              </div>
            </div>
          </div>

          {/* Findings Diff List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <h3 className="text-xs font-bold text-primary uppercase tracking-wider">
                DETAILED TRANSITIONS // {activeTab.toUpperCase()}
              </h3>
              <button
                onClick={() => setActiveTab('all')}
                className="text-[11px] text-[#A89F82] hover:text-primary underline cursor-pointer"
              >
                [SHOW ALL ({summary.new_count + summary.resolved_count + summary.persistent_count + summary.regressed_count})]
              </button>
            </div>

            {/* Render Items */}
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {(activeTab === 'all' || activeTab === 'new') && findings.new.map(f => (
                <div key={f.id} className="p-3 bg-[#1C0E00] border-l-4 border-[#FFA044] border border-border">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.2 bg-[#3B1B00] text-[#FFA044] font-bold text-[10px]">+ NEW</span>
                      <span className="text-[#FFA044] font-bold">[{f.severity}]</span>
                      <span className="text-[#FFF8DB] font-bold">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-[#7A7256]">{f.cwe || 'CWE-693'}</span>
                  </div>
                  <div className="text-[11px] text-[#C7B988] mt-1">{f.description}</div>
                </div>
              ))}

              {(activeTab === 'all' || activeTab === 'resolved') && findings.resolved.map(f => (
                <div key={f.id} className="p-3 bg-[#0A1800] border-l-4 border-[#84CC16] border border-border">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.2 bg-[#1B3304] text-[#84CC16] font-bold text-[10px]">- RESOLVED</span>
                      <span className="text-[#84CC16] font-bold">[{f.severity}]</span>
                      <span className="text-[#FFF8DB] line-through">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-lime-400 font-bold">[CONFIRMED FIXED]</span>
                  </div>
                  <div className="text-[11px] text-[#A89F82] mt-1">Successfully assessed in target audit without recurrence.</div>
                </div>
              ))}

              {(activeTab === 'all' || activeTab === 'persistent') && findings.persistent.map(f => (
                <div key={f.id} className="p-3 bg-[#121004] border-l-4 border-primary border border-border">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.2 bg-[#2B2300] text-primary font-bold text-[10px]">= PERSISTENT</span>
                      <span className="text-primary font-bold">[{f.severity}]</span>
                      <span className="text-[#FFF8DB]">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-[#7A7256]">{f.owasp}</span>
                  </div>
                  <div className="text-[11px] text-[#C7B988] mt-1">{f.remediation}</div>
                </div>
              ))}

              {(activeTab === 'all' || activeTab === 'regressed') && findings.regressed.map(f => (
                <div key={f.id} className="p-3 bg-[#260505] border-l-4 border-[#FF4444] border border-border">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.2 bg-[#440B0B] text-[#FF6666] font-bold text-[10px]">&circlearrowright; REGRESSED</span>
                      <span className="text-[#FF4444] font-bold">[{f.severity}]</span>
                      <span className="text-[#FFF8DB] font-bold">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-red-400 font-bold">[RE-INTRODUCED DEFECT]</span>
                  </div>
                  <div className="text-[11px] text-[#FFAAAA] mt-1">Previously fixed or absent in base audit; reappeared in target audit.</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-end px-6 py-3.5 bg-[#0D0D0D] border-t border-border">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-primary text-black text-xs font-bold uppercase tracking-wider hover:bg-[#FFE033] transition cursor-pointer"
          >
            [CLOSE COMPARISON]
          </button>
        </div>
      </div>
    </div>
  );
};
