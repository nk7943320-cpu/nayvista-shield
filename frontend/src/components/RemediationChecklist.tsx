import React, { useState, useEffect } from 'react';
import { CheckSquare, Square, Clock, CheckCircle2, ShieldCheck, AlertTriangle } from 'lucide-react';
import { RemediationItem, RemediationState, Severity } from '../types';
import { getRemediationItems, updateRemediationItem } from '../api';

interface RemediationChecklistProps {
  scanId: string;
  onInspectFinding?: (findingId: string) => void;
}

const severityColors: Record<Severity, string> = {
  CRITICAL: 'text-[#FF4444] border-[#FF4444]',
  HIGH: 'text-[#FFA044] border-[#FFA044]',
  MEDIUM: 'text-[#FFD400] border-[#FFD400]',
  LOW: 'text-[#84CC16] border-[#84CC16]',
  INFO: 'text-[#9EABB8] border-[#9EABB8]',
};

export const RemediationChecklist: React.FC<RemediationChecklistProps> = ({ scanId, onInspectFinding }) => {
  const [items, setItems] = useState<RemediationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterState, setFilterState] = useState<'ALL' | RemediationState>('ALL');

  useEffect(() => {
    loadItems();
  }, [scanId]);

  const loadItems = async () => {
    try {
      setLoading(true);
      const res = await getRemediationItems(scanId);
      setItems(res);
    } catch (err) {
      console.error('Failed to load remediation items:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleState = async (item: RemediationItem) => {
    // Cycle state: OPEN -> IN_PROGRESS -> COMPLETED -> OPEN
    let nextState: RemediationState = 'IN_PROGRESS';
    if (item.state === 'OPEN') nextState = 'IN_PROGRESS';
    else if (item.state === 'IN_PROGRESS') nextState = 'COMPLETED';
    else nextState = 'OPEN';

    try {
      const updated = await updateRemediationItem(scanId, item.finding_id, nextState);
      setItems(prev => prev.map(it => (it.finding_id === item.finding_id ? updated : it)));
    } catch (err) {
      console.error('Failed to update item state:', err);
    }
  };

  const filteredItems = items.filter(it => {
    if (filterState === 'ALL') return true;
    return it.state === filterState;
  });

  const completedCount = items.filter(it => it.state === 'COMPLETED').length;
  const inProgressCount = items.filter(it => it.state === 'IN_PROGRESS').length;
  const openCount = items.filter(it => it.state === 'OPEN').length;

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Header Summary */}
      <div className="bg-[#0A0A0A] border-2 border-border p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary font-bold uppercase tracking-widest text-[11px] mb-1">
            <CheckSquare className="w-4 h-4" />
            <span>AUDIT REMEDIATION // ACTION CHECKLIST</span>
          </div>
          <h2 className="text-xl font-bold text-[#FFF8DB]">
            Defensive Implementation Roadmap
          </h2>
          <p className="text-[#A89F82] text-xs mt-0.5">
            Explicitly track engineering remediation tasks. Tasks are preserved independently of scanner runs.
          </p>
        </div>

        {/* Progress Bar & Counters */}
        <div className="flex items-center space-x-3 bg-[#050505] p-3 border border-border">
          <div className="text-center px-2">
            <div className="text-lg font-extrabold text-[#84CC16]">{completedCount}</div>
            <div className="text-[9px] text-[#7A7256] uppercase">DONE</div>
          </div>
          <div className="text-center px-2 border-l border-border">
            <div className="text-lg font-extrabold text-amber-400">{inProgressCount}</div>
            <div className="text-[9px] text-[#7A7256] uppercase">IN PROGRESS</div>
          </div>
          <div className="text-center px-2 border-l border-border">
            <div className="text-lg font-extrabold text-[#FF6666]">{openCount}</div>
            <div className="text-[9px] text-[#7A7256] uppercase">OPEN</div>
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 border-b border-border pb-2">
        <span className="text-[10px] text-[#7A7256] uppercase font-bold mr-2">FILTER TASKS:</span>
        {(['ALL', 'OPEN', 'IN_PROGRESS', 'COMPLETED'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setFilterState(tab)}
            className={`px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider border transition cursor-pointer ${
              filterState === tab
                ? 'bg-primary text-black border-primary'
                : 'bg-[#0A0A0A] text-[#A89F82] border-border hover:text-[#FFF8DB]'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Checklist Items */}
      {loading ? (
        <div className="p-8 text-center text-[#7A7256] bg-[#0A0A0A] border border-border">
          Loading remediation checklist...
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="p-8 text-center text-[#7A7256] bg-[#0A0A0A] border border-border">
          No remediation tasks match the selected filter.
        </div>
      ) : (
        <div className="space-y-2">
          {filteredItems.map((item, idx) => {
            const isCompleted = item.state === 'COMPLETED';
            const isInProgress = item.state === 'IN_PROGRESS';

            return (
              <div
                key={item.finding_id || idx}
                className={`p-3.5 border transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  isCompleted
                    ? 'bg-[#081203] border-[#254E0A]/60'
                    : isInProgress
                    ? 'bg-[#140F03] border-amber-500/40'
                    : 'bg-[#0A0A0A] border-border hover:border-primary/40'
                }`}
              >
                <div className="flex items-start space-x-3">
                  {/* Status Toggle Button */}
                  <button
                    onClick={() => handleToggleState(item)}
                    className="mt-0.5 text-primary hover:text-[#FFE033] transition cursor-pointer"
                    title="Click to cycle status (Open -> In Progress -> Completed)"
                  >
                    {isCompleted ? (
                      <CheckCircle2 className="w-5 h-5 text-lime-400" />
                    ) : isInProgress ? (
                      <Clock className="w-5 h-5 text-amber-400 animate-pulse" />
                    ) : (
                      <Square className="w-5 h-5 text-[#4A4535] hover:text-primary" />
                    )}
                  </button>

                  <div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-1.5 py-0.2 border text-[9px] font-bold ${severityColors[item.severity]}`}>
                        [{item.severity}]
                      </span>
                      <span className={`text-xs font-bold ${isCompleted ? 'line-through text-[#7A7256]' : 'text-[#FFF8DB]'}`}>
                        {item.title}
                      </span>
                      <span className="text-[10px] text-[#A89F82]">
                        // {item.component}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#C7B988] mt-1 pl-0.5 leading-relaxed">
                      &bull; {item.action}
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2 self-end sm:self-center shrink-0">
                  <span
                    className={`px-2 py-0.5 text-[9px] font-bold uppercase border ${
                      isCompleted
                        ? 'bg-[#102404] text-lime-400 border-[#254E0A]'
                        : isInProgress
                        ? 'bg-amber-950/40 text-amber-400 border-amber-500/50'
                        : 'bg-[#121212] text-[#7A7256] border-border'
                    }`}
                  >
                    [{item.state.replace('_', ' ')}]
                  </span>

                  {onInspectFinding && (
                    <button
                      onClick={() => onInspectFinding(item.finding_id)}
                      className="px-2 py-0.5 bg-[#141414] hover:bg-[#222] border border-border text-[10px] text-[#C7B988] hover:text-primary uppercase tracking-wider transition cursor-pointer"
                    >
                      [INSPECT]
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
