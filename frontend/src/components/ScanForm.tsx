import React, { useState } from 'react';
import { Terminal, Shield, Lock, AlertTriangle, ArrowRight, ShieldCheck, Database, Zap } from 'lucide-react';

interface ScanFormProps {
  onStartScan: (target: string, authorized: boolean, mode?: string) => Promise<void>;
  isLoading: boolean;
  error?: string | null;
}

export const ScanForm: React.FC<ScanFormProps> = ({ onStartScan, isLoading, error }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [selectedMode, setSelectedMode] = useState<'DEFENSIVE / SAFE' | 'ACTIVE / AUTHORIZED TESTING'>('DEFENSIVE / SAFE');
  const [localError, setLocalError] = useState<{ message: string; category?: string; code?: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!targetUrl.trim()) {
      setLocalError({
        message: 'Please specify a target website URL (e.g., https://example.com).',
        category: 'VALIDATION_ERROR',
        code: 'MISSING_TARGET',
      });
      return;
    }

    if (!authorized) {
      setLocalError({
        message: 'You must confirm explicit authorization before launching a security assessment.',
        category: 'VALIDATION_ERROR',
        code: 'UNAUTHORIZED_SUBMISSION',
      });
      return;
    }

    try {
      await onStartScan(targetUrl.trim(), authorized, selectedMode);
    } catch (err: any) {
      setLocalError({
        message: err.message || 'Failed to initialize security assessment.',
        category: err.category,
        code: err.code,
      });
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4 sm:px-6">
      {/* Console Header Banner */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-[#0A0A0A] border border-primary/50 text-primary text-xs font-bold uppercase tracking-widest mb-3 glow-yellow-sm">
          <Terminal className="w-3.5 h-3.5" />
          <span>OPERATIONS SECURITY CONSOLE</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-[#FFF8DB] mb-2">
          NAYVISTA <span className="text-primary">SHIELD</span>
        </h1>
        <p className="text-base sm:text-lg font-medium text-primary tracking-wide mb-2">
          AI-Assisted Web Security Assessment
        </p>
        <p className="text-xs sm:text-sm text-[#A89F82] max-w-2xl mx-auto tracking-normal">
          Authorized, defensive cybersecurity vulnerability assessment platform developed by NayVista Technologies. Strictly scoped to authorized targets with zero destructive payloads.
        </p>
      </div>

      {/* Main Terminal Box */}
      <div className="bg-[#0A0A0A] border-2 border-border hover:border-primary/40 transition-colors p-6 sm:p-8 shadow-2xl relative">
        {/* Terminal Header Bar */}
        <div className="flex items-center justify-between pb-4 mb-6 border-b border-border text-xs text-[#7A7256]">
          <div className="flex items-center space-x-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-600/80 inline-block"></span>
            <span className="h-2.5 w-2.5 rounded-full bg-yellow-500/80 inline-block"></span>
            <span className="h-2.5 w-2.5 rounded-full bg-green-500/80 inline-block"></span>
            <span className="ml-2 font-mono text-[#C7B988]">AUDIT_DISCOVERY // SESSION_INIT</span>
          </div>
          <span className="text-primary text-[11px] font-bold tracking-wider uppercase">
            {selectedMode === 'ACTIVE / AUTHORIZED TESTING' ? 'ACTIVE_AUTHORIZED_MODE' : 'SAFE_DEFENSIVE_MODE'}
          </span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target Input */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label htmlFor="target-url" className="block text-xs font-bold text-[#FFF8DB] uppercase tracking-wider">
                Target Origin URL
              </label>
              <span className="text-[11px] text-[#7A7256] font-mono">Format: https://domain.tld</span>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-primary font-bold">
                &gt;
              </div>
              <input
                id="target-url"
                type="text"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isLoading}
                className="block w-full pl-9 pr-4 py-3.5 bg-[#030303] border border-border focus:border-primary focus:outline-none text-[#FFF8DB] placeholder-[#4A4535] text-sm font-mono tracking-wide transition"
              />
            </div>
            <p className="mt-2 text-[11px] text-[#7A7256]">
              Same-origin boundary enforcement active: Subdomains and cross-origin endpoints will not be queried.
            </p>
          </div>

          {/* Assessment Mode Selector */}
          <div>
            <label className="block text-xs font-bold text-[#FFF8DB] uppercase tracking-wider mb-2">
              Assessment Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* Card 1: DEFENSIVE / SAFE */}
              <div
                onClick={() => setSelectedMode('DEFENSIVE / SAFE')}
                className={`p-3.5 relative cursor-pointer transition-all ${
                  selectedMode === 'DEFENSIVE / SAFE'
                    ? 'border-2 border-primary bg-[#0E0C04]'
                    : 'border border-border bg-[#050505] hover:border-primary/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`font-bold text-xs flex items-center space-x-1.5 ${selectedMode === 'DEFENSIVE / SAFE' ? 'text-primary' : 'text-[#FFF8DB]'}`}>
                    <span className={`h-2 w-2 rounded-full inline-block ${selectedMode === 'DEFENSIVE / SAFE' ? 'bg-primary' : 'bg-gray-500'}`}></span>
                    <span>DEFENSIVE / SAFE</span>
                  </span>
                  <span className="text-[10px] font-bold text-[#38D39F] bg-[#0E2818] border border-[#165030] px-1.5 py-0.5 uppercase tracking-wider">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-[#C7B988] leading-relaxed">
                  Passive audit: DNS &amp; IP resolution, standard service port exposure, HTTP security headers, TLS ciphers, cookie security, crawl &amp; surface inventory. Zero destructive traffic.
                </p>
              </div>

              {/* Card 2: ACTIVE / AUTHORIZED TESTING */}
              <div
                onClick={() => setSelectedMode('ACTIVE / AUTHORIZED TESTING')}
                className={`p-3.5 relative cursor-pointer transition-all ${
                  selectedMode === 'ACTIVE / AUTHORIZED TESTING'
                    ? 'border-2 border-primary bg-[#0E0C04]'
                    : 'border border-border bg-[#050505] hover:border-primary/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={`font-bold text-xs flex items-center space-x-1.5 ${selectedMode === 'ACTIVE / AUTHORIZED TESTING' ? 'text-primary' : 'text-[#FFF8DB]'}`}>
                    <span className={`h-2 w-2 rounded-full inline-block ${selectedMode === 'ACTIVE / AUTHORIZED TESTING' ? 'bg-primary' : 'bg-gray-500'}`}></span>
                    <span>ACTIVE / AUTHORIZED</span>
                  </span>
                  <span className="text-[10px] font-bold text-[#38D39F] bg-[#0E2818] border border-[#165030] px-1.5 py-0.5 uppercase tracking-wider">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-[#C7B988] leading-relaxed">
                  Bounded active validation: HTTP behavior, TLS strength, CORS, API security, auth review, access controls, infrastructure exposures. Non-destructive, rate-governed.
                </p>
              </div>

              {/* Card 3: ATTACK SIMULATION */}
              <div className="border border-border bg-[#050505] p-3.5 opacity-60 cursor-not-allowed select-none relative">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold text-xs text-[#7A7256] flex items-center space-x-1.5">
                    <span className="h-2 w-2 rounded-full bg-[#555] inline-block"></span>
                    <span>ATTACK SIMULATION</span>
                  </span>
                  <span className="text-[10px] font-bold text-[#FFA3A3] bg-[#2B0B0B] border border-[#5C1414] px-1.5 py-0.5 uppercase tracking-wider">
                    COMING SOON
                  </span>
                </div>
                <p className="text-[11px] text-[#666] leading-relaxed">
                  Coming in a future authorized-testing phase. Reserved for penetration testing and unrestricted exploitation.
                </p>
              </div>
            </div>
          </div>

          {/* Authorization Checkbox */}
          <div className="bg-[#050505] border border-border p-4">
            <label className="flex items-start space-x-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                disabled={isLoading}
                className="mt-0.5 h-4 w-4 rounded-none border border-primary bg-black text-primary focus:ring-0 cursor-pointer accent-[#FFD400]"
              />
              <span className="text-xs font-semibold text-[#FFF8DB] leading-relaxed">
                {selectedMode === 'ACTIVE / AUTHORIZED TESTING'
                  ? 'I confirm I am authorized to security-test this website in ACTIVE mode.'
                  : 'I confirm I am authorized to security-test this website.'}
                <span className="block text-[11px] font-normal text-[#A89F82] mt-0.5">
                  {selectedMode === 'ACTIVE / AUTHORIZED TESTING'
                    ? 'I understand this active assessment performs bounded, non-destructive validation probes (max 4 concurrent, max 100 requests) strictly within same-origin boundaries and is logged in the permanent audit trail.'
                    : 'I understand this defensive assessment strictly adheres to same-origin boundaries and is logged in the permanent audit trail.'}
                </span>
              </span>
            </label>
          </div>

          {/* Domain-Aware Fault Banner */}
          {(() => {
            const activeErr = localError || (error ? { message: error } : null);
            if (!activeErr) return null;

            const msg = activeErr.message || '';
            const msgLower = msg.toLowerCase();
            let category = activeErr.category;
            if (!category) {
              if (
                msgLower.includes('reach') ||
                msgLower.includes('timed out') ||
                msgLower.includes('timeout') ||
                msgLower.includes('unreachable') ||
                msgLower.includes('econnrefused') ||
                msgLower.includes('connection refused') ||
                msgLower.includes('dns')
              ) {
                category = 'ASSESSMENT_LIMITATION';
              } else if (
                msgLower.includes('api') ||
                msgLower.includes('proxy') ||
                msgLower.includes('backend') ||
                msgLower.includes('connect to nayvista shield') ||
                msgLower.includes('empty response') ||
                msgLower.includes('malformed') ||
                msgLower.includes('internal server')
              ) {
                category = 'PLATFORM_FAILURE';
              } else {
                category = 'VALIDATION_ERROR';
              }
            }

            const isPlatform = category === 'PLATFORM_FAILURE';
            const isLimitation = category === 'ASSESSMENT_LIMITATION';

            return (
              <div
                className={`p-4 text-xs space-y-3 border ${
                  isPlatform
                    ? 'bg-[#1A0808] border-[#6B1717] text-[#FFA3A3]'
                    : isLimitation
                    ? 'bg-[#161305] border-[#8C7300] text-[#FFF8DB]'
                    : 'bg-[#141208] border-[#665214] text-[#E8DEC0]'
                }`}
              >
                <div
                  className={`flex items-center justify-between border-b pb-2 ${
                    isPlatform
                      ? 'border-[#4A1010]'
                      : isLimitation
                      ? 'border-[#4A3D0B]'
                      : 'border-[#33290A]'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <AlertTriangle
                      className={`w-4 h-4 flex-shrink-0 ${
                        isPlatform
                          ? 'text-[#FF4444]'
                          : isLimitation
                          ? 'text-primary'
                          : 'text-[#E5B533]'
                      }`}
                    />
                    <span
                      className={`font-bold tracking-widest uppercase font-mono ${
                        isPlatform
                          ? 'text-[#FF6B6B]'
                          : isLimitation
                          ? 'text-primary'
                          : 'text-[#E5B533]'
                      }`}
                    >
                      {isPlatform
                        ? '[ ASSESSMENT SERVICE UNAVAILABLE ]'
                        : isLimitation
                        ? '[ ASSESSMENT LIMITED ]'
                        : '[ TARGET VALIDATION ERROR ]'}
                    </span>
                  </div>
                  <span className="text-[10px] text-[#A89F82] font-mono uppercase tracking-wider">
                    {isPlatform
                      ? 'STATUS: PLATFORM ERROR'
                      : isLimitation
                      ? 'STATUS: TARGET REACHABILITY'
                      : 'STATUS: VALIDATION ERROR'}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <p className="font-semibold text-[#FFF8DB]">
                    {isPlatform
                      ? 'Unable to communicate with the assessment service.'
                      : isLimitation
                      ? 'Target could not be reached or connectivity was constrained.'
                      : 'Target URL or authorization parameters were rejected.'}
                  </p>
                  <div
                    className={`p-2.5 border font-mono text-[11px] break-words ${
                      isPlatform
                        ? 'bg-[#0D0404] border-[#3D0D0D] text-[#FFC4C4]'
                        : isLimitation
                        ? 'bg-[#0D0B03] border-[#3D3305] text-[#FFE899]'
                        : 'bg-[#0A0904] border-[#2E2405] text-[#E5D7A3]'
                    }`}
                  >
                    <span className="font-bold">Reason: </span>
                    {msg}
                  </div>
                </div>

                <div className="space-y-1 text-[11px]">
                  <span className="font-bold uppercase tracking-wider text-[10px] text-[#A89F82] block">
                    Possible causes:
                  </span>
                  <ul className="list-disc list-inside space-y-0.5 text-[#D4C8A5] pl-1 font-mono text-[10.5px]">
                    {isPlatform ? (
                      <>
                        <li>Assessment API service unavailable</li>
                        <li>Backend/proxy failure</li>
                        <li>Network interruption to Shield server</li>
                      </>
                    ) : isLimitation ? (
                      <>
                        <li>Target server is offline or unreachable</li>
                        <li>Target DNS resolution failed</li>
                        <li>Target firewall dropped connection or timed out</li>
                        <li>Connection refused by remote target host</li>
                      </>
                    ) : (
                      <>
                        <li>Invalid or unsupported URL scheme (must be http:// or https://)</li>
                        <li>Target resolves to private or restricted network (SSRF Guard)</li>
                        <li>Explicit testing authorization required</li>
                      </>
                    )}
                  </ul>
                  {isLimitation && (
                    <p className="text-[10px] text-primary/80 italic font-mono pt-1">
                      Note: This is a target reachability constraint. The NayVista Shield platform and API are fully operational.
                    </p>
                  )}
                </div>

                <div className="pt-1 flex items-center justify-end">
                  <button
                    type="submit"
                    disabled={isLoading || !targetUrl.trim() || !authorized}
                    className={`inline-flex items-center space-x-1.5 px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider transition cursor-pointer border font-mono disabled:opacity-50 disabled:cursor-not-allowed ${
                      isPlatform
                        ? 'bg-[#2E0B0B] hover:bg-[#451010] border-[#7A1C1C] text-[#FFF8DB]'
                        : 'bg-[#2E2405] hover:bg-[#423407] border-[#8C7300] text-primary'
                    }`}
                  >
                    <span>[ RETRY ]</span>
                  </button>
                </div>
              </div>
            );
          })()}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading || !targetUrl.trim() || !authorized}
            className={`w-full py-3.5 px-6 font-bold text-xs uppercase tracking-widest flex items-center justify-center space-x-3 transition duration-150 border ${
              isLoading || !targetUrl.trim() || !authorized
                ? 'bg-[#141414] text-[#5A523A] border-[#26200A] cursor-not-allowed'
                : 'bg-primary text-black border-primary hover:bg-[#FFE033] hover:shadow-[0_0_20px_rgba(255,212,0,0.3)] cursor-pointer active:scale-[0.99]'
            }`}
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin"></div>
                <span>INITIALIZING ASSESSMENT PIPELINE...</span>
              </>
            ) : (
              <>
                <span>INITIALIZE SECURITY ASSESSMENT</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </div>

      {/* Defensive Boundary Spec Badges */}
      <div className="mt-8 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="bg-[#0A0A0A] border border-border p-3.5">
          <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-wider mb-1">
            <ShieldCheck className="w-4 h-4" />
            <span>01 SAME-ORIGIN SCOPE</span>
          </div>
          <p className="text-[11px] text-[#A89F82] leading-relaxed">
            Strict domain boundary enforcement with anti-SSRF protections. External redirects and third-party scripts are never scanned.
          </p>
        </div>

        <div className="bg-[#0A0A0A] border border-border p-3.5">
          <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-wider mb-1">
            <Lock className="w-4 h-4" />
            <span>02 SAFE AUDITING</span>
          </div>
          <p className="text-[11px] text-[#A89F82] leading-relaxed">
            Non-destructive passive inspection. Zero exploit payloads, zero password cracking, and zero account takeover routines.
          </p>
        </div>

        <div className="bg-[#0A0A0A] border border-border p-3.5">
          <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-wider mb-1">
            <Zap className="w-4 h-4" />
            <span>03 AI ANALYSIS</span>
          </div>
          <p className="text-[11px] text-[#A89F82] leading-relaxed">
            Structured scoring (0-100), OWASP mapping, sensitive data redaction, and deterministic remediation recommendations.
          </p>
        </div>
      </div>
    </div>
  );
};
