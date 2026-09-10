import React from 'react';
import { Terminal, History, Activity } from 'lucide-react';
import logoUrl from '../assets/logo.png';

interface HeaderProps {
  currentView: 'scan' | 'dashboard' | 'history';
  onNavigate: (view: 'scan' | 'dashboard' | 'history') => void;
  hasActiveScan: boolean;
}

export const Header: React.FC<HeaderProps> = ({ currentView, onNavigate, hasActiveScan }) => {
  return (
    <header className="border-b border-border bg-[#050505]/95 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onNavigate('scan')}>
          <div className="h-10 w-10 border border-primary bg-primary/10 flex items-center justify-center glow-yellow-sm overflow-hidden p-0.5">
            <img src={logoUrl} alt="NayVista Shield Logo" className="h-full w-full object-contain" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-sm sm:text-base tracking-wider text-[#FFF8DB]">
                NAYVISTA <span className="text-primary">SHIELD</span>
              </span>
              <span className="hidden sm:inline-block text-[10px] font-bold tracking-widest px-1.5 py-0.5 bg-[#1F1B05] text-primary border border-primary/40 uppercase">
                DEFENSE v1.0
              </span>
            </div>
            <p className="text-[11px] text-[#A89F82] tracking-tight hidden md:block">
              AI-Assisted Web Security Assessment &bull; NayVista Technologies
            </p>
          </div>
        </div>

        {/* System telemetry indicator & navigation */}
        <div className="flex items-center space-x-2 sm:space-x-6">
          <div className="hidden lg:flex items-center space-x-2 text-[11px] text-[#A89F82] px-2.5 py-1 border border-border bg-[#0A0A0A]">
            <span className="h-2 w-2 rounded-full bg-lime-500 animate-pulse"></span>
            <span className="text-[#C7B988]">CORE:</span>
            <span className="text-primary font-semibold">SAFE.ONLINE</span>
          </div>

          <nav className="flex items-center space-x-1 sm:space-x-2">
            <button
              onClick={() => onNavigate('scan')}
              className={`px-2 sm:px-3 py-1.5 text-xs font-semibold uppercase tracking-wider flex items-center space-x-1 sm:space-x-1.5 transition border ${
                currentView === 'scan'
                  ? 'bg-primary/10 text-primary border-primary glow-yellow-sm'
                  : 'text-[#C7B988] hover:text-[#FFF8DB] hover:bg-[#121212] border-transparent'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Console</span>
            </button>

            {hasActiveScan && (
              <button
                onClick={() => onNavigate('dashboard')}
                className={`px-2 sm:px-3 py-1.5 text-xs font-semibold uppercase tracking-wider flex items-center space-x-1 sm:space-x-1.5 transition border ${
                  currentView === 'dashboard'
                    ? 'bg-primary/10 text-primary border-primary glow-yellow-sm'
                    : 'text-[#C7B988] hover:text-[#FFF8DB] hover:bg-[#121212] border-transparent'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Results</span>
              </button>
            )}

            <button
              onClick={() => onNavigate('history')}
              className={`px-2 sm:px-3 py-1.5 text-xs font-semibold uppercase tracking-wider flex items-center space-x-1 sm:space-x-1.5 transition border ${
                currentView === 'history'
                  ? 'bg-primary/10 text-primary border-primary glow-yellow-sm'
                  : 'text-[#C7B988] hover:text-[#FFF8DB] hover:bg-[#121212] border-transparent'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span className="hidden xs:inline sm:inline">Audit Log</span>
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
};
