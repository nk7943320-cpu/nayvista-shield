import React from 'react';
import { Terminal, Globe, StopCircle, Layers, CheckSquare, Square, Play } from 'lucide-react';
import { ProgressStep } from '../types';

interface ScanProgressProps {
  target: string;
  progress?: ProgressStep;
  onCancel?: () => void;
  status: string;
  mode?: string;
}

const PHASES = [
  { key: 'validation', label: 'TARGET VALIDATION', step: 1 },
  { key: 'dns', label: 'DNS RESOLUTION', step: 2 },
  { key: 'scope', label: 'SCOPE VALIDATION', step: 3 },
  { key: 'ip_exposure', label: 'IP EXPOSURE ANALYSIS', step: 4 },
  { key: 'port_exposure', label: 'NETWORK PORT EXPOSURE', step: 5 },
  { key: 'headers', label: 'HTTP SECURITY ANALYSIS', step: 6 },
  { key: 'tls', label: 'HTTPS / TLS ANALYSIS', step: 7 },
  { key: 'cookies', label: 'COOKIE SECURITY', step: 8 },
  { key: 'crawling', label: 'WEB CRAWLING', step: 9 },
  { key: 'information', label: 'INFORMATION EXPOSURE', step: 10 },
  { key: 'surface', label: 'INFRASTRUCTURE EXPOSURE', step: 11 },
  { key: 'correlation', label: 'FINDING CORRELATION', step: 12 },
  { key: 'scoring', label: 'SECURITY POSTURE SCORING', step: 13 },
  { key: 'report', label: 'REPORT GENERATION', step: 14 },
];

export const ScanProgress: React.FC<ScanProgressProps> = ({ target, progress, onCancel, status, mode }) => {
  const currentStep = progress?.step || 1;
  const totalSteps = progress?.total_steps || 14;
  const pagesDiscovered = progress?.stats?.pages_discovered || 1;
  const percentComplete = Math.min(100, Math.round((currentStep / totalSteps) * 100));

  return (
    <div className="max-w-3xl mx-auto py-10 px-4 sm:px-6">
      <div className="bg-[#0A0A0A] border-2 border-primary/50 p-6 sm:p-8 shadow-2xl relative">
        {/* Terminal Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-border pb-5 mb-6 gap-4">
          <div>
            <div className="flex items-center space-x-2 text-primary text-xs uppercase font-bold tracking-widest mb-1.5">
              <span className="h-2 w-2 rounded-full bg-primary animate-ping inline-block"></span>
              <span>ASSESSMENT IN PROGRESS // STAGE {currentStep}/{totalSteps}</span>
              <span className="text-[#A89F82] font-normal">|</span>
              <span className="text-[#38D39F] font-mono font-bold">{mode || 'DEFENSIVE / SAFE'}</span>
            </div>
            <div className="text-lg sm:text-xl font-bold text-[#FFF8DB] flex items-center space-x-2 font-mono">
              <span className="text-primary">&gt;</span>
              <span className="break-all">{target}</span>
            </div>
          </div>

          {onCancel && status === 'running' && (
            <button
              onClick={onCancel}
              className="inline-flex items-center space-x-2 px-3 py-1.5 border border-[#5C1414] bg-[#2B0B0B] text-[#FFA3A3] text-xs font-bold uppercase tracking-wider hover:bg-[#3D0F0F] transition self-start sm:self-center cursor-pointer"
            >
              <StopCircle className="w-4 h-4" />
              <span>ABORT AUDIT</span>
            </button>
          )}
        </div>

        {/* Segmented Terminal Progress Bar */}
        <div className="mb-6">
          <div className="flex justify-between text-xs text-[#C7B988] mb-2 font-mono">
            <span>{progress?.message ? `[EXEC] ${progress.message}` : '[EXEC] Running automated security audit pipeline...'}</span>
            <span className="text-primary font-bold">{percentComplete}%</span>
          </div>
          <div className="w-full bg-[#030303] border border-border h-3 p-0.5">
            <div
              className="bg-primary h-full transition-all duration-300"
              style={{ width: `${percentComplete}%` }}
            ></div>
          </div>
        </div>

        {/* Telemetry metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-6">
          <div className="bg-[#050505] border border-border p-3">
            <div className="text-[10px] text-[#7A7256] uppercase tracking-wider font-bold">PAGES AUDITED</div>
            <div className="text-xl font-bold text-primary mt-1 flex items-center space-x-2 font-mono">
              <Layers className="w-4 h-4 text-[#A89F82]" />
              <span>{pagesDiscovered}</span>
            </div>
          </div>

          <div className="bg-[#050505] border border-border p-3">
            <div className="text-[10px] text-[#7A7256] uppercase tracking-wider font-bold">CURRENT PHASE</div>
            <div className="text-xs font-bold text-[#FFF8DB] mt-2 font-mono uppercase truncate">
              {progress?.phase || 'VALIDATION'}
            </div>
          </div>

          <div className="bg-[#050505] border border-border p-3 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-[#7A7256] uppercase tracking-wider font-bold">COMPLETED STEPS</div>
            <div className="text-xl font-bold text-primary mt-1 font-mono">
              {Math.min(totalSteps, currentStep)} / {totalSteps}
            </div>
          </div>
        </div>

        {/* 10-Step Workflow Checklist */}
        <div className="space-y-2">
          <div className="text-[11px] font-bold text-[#7A7256] uppercase tracking-wider mb-2 font-mono">
            --- ASSESSMENT CHECKLIST ---
          </div>
          {PHASES.map((phase) => {
            const isCompleted = currentStep > phase.step;
            const isCurrent = currentStep === phase.step;

            return (
              <div
                key={phase.key}
                className={`flex items-center justify-between p-2.5 text-xs font-mono border transition ${
                  isCurrent
                    ? 'bg-[#181504] border-primary text-primary glow-yellow-sm font-bold'
                    : isCompleted
                    ? 'bg-[#050505] border-[#1C1805] text-[#C7B988]'
                    : 'bg-black border-[#141205] text-[#4A4535]'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <span className="text-[10px] font-bold opacity-70">
                    {String(phase.step).padStart(2, '0')}
                  </span>
                  <span>{phase.label}</span>
                </div>

                <div>
                  {isCompleted ? (
                    <span className="text-lime-400 font-bold">[✓ OK]</span>
                  ) : isCurrent ? (
                    <span className="text-primary font-bold animate-pulse">[▶ RUN]</span>
                  ) : (
                    <span className="text-[#333]">[ PEND ]</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
