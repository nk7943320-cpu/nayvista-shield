import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { ScanForm } from './components/ScanForm';
import { ScanProgress } from './components/ScanProgress';
import { DashboardOverview } from './components/DashboardOverview';
import { FindingsList } from './components/FindingsList';
import { SurfaceInventoryView } from './components/SurfaceInventoryView';
import { ScanHistory } from './components/ScanHistory';
import { ReportModal } from './components/ReportModal';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ScanComparisonModal } from './components/ScanComparisonModal';
import { RemediationChecklist } from './components/RemediationChecklist';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ScanRecord, Finding, ScanComparison, FindingStatus } from './types';
import {
  startScan,
  getScan,
  getFindings,
  getScanHistory,
  cancelScan,
  compareScans,
  updateFindingStatus,
} from './api';

export function App() {
  const [currentView, setCurrentView] = useState<'scan' | 'dashboard' | 'history'>('scan');
  const [dashboardTab, setDashboardTab] = useState<'overview' | 'findings' | 'surface' | 'remediation'>('overview');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanRecord | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [isFormSubmitting, setIsFormSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Modals state
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportScanTarget, setReportScanTarget] = useState<ScanRecord | null>(null);
  const [selectedFindingForDetail, setSelectedFindingForDetail] = useState<Finding | null>(null);
  const [comparisonData, setComparisonData] = useState<ScanComparison | null>(null);

  const pollIntervalRef = useRef<any>(null);

  const isValidScanId = (id: unknown): id is string => {
    if (typeof id !== 'string') return false;
    const trimmed = id.trim();
    if (!trimmed || trimmed === 'undefined' || trimmed === 'null') return false;
    return /^[a-zA-Z0-9_-]{1,64}$/.test(trimmed);
  };

  // Load scan history and recover any active scan from localStorage on page load
  useEffect(() => {
    loadHistory();
    const savedScanId = localStorage.getItem('nshield_active_scan_id');
    if (savedScanId) {
      resumeActiveScan(savedScanId);
    }
  }, []);

  const resumeActiveScan = async (scanId: string) => {
    if (!isValidScanId(scanId)) {
      localStorage.removeItem('nshield_active_scan_id');
      return;
    }

    try {
      const scan = await getScan(scanId);
      if (!scan) {
        localStorage.removeItem('nshield_active_scan_id');
        return;
      }
      if (scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued') {
        setActiveScanId(scanId);
        setCurrentScan(scan);
        setIsScanning(true);
      } else if (scan.status === 'completed') {
        setActiveScanId(scanId);
        setCurrentScan(scan);
        const f = await getFindings(scanId);
        setFindings(f);
        setCurrentView('dashboard');
        setDashboardTab('overview');
        localStorage.removeItem('nshield_active_scan_id');
      } else {
        localStorage.removeItem('nshield_active_scan_id');
      }
    } catch {
      localStorage.removeItem('nshield_active_scan_id');
      setActiveScanId(null);
      setIsScanning(false);
    }
  };

  const loadHistory = async () => {
    try {
      const pastScans = await getScanHistory();
      setHistory(pastScans.scans);
    } catch {
      // Ignore initial history failure if server not up yet
    }
  };

  // Poll active scan status with bounded failure tolerance and cleanup
  useEffect(() => {
    if (!activeScanId || !isScanning) return;

    let consecutiveFailures = 0;
    const MAX_CONSECUTIVE_FAILURES = 5;

    const poll = async () => {
      try {
        const scan = await getScan(activeScanId);
        consecutiveFailures = 0;
        setCurrentScan(scan);

        if (scan.status === 'completed') {
          setIsScanning(false);
          localStorage.removeItem('nshield_active_scan_id');
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
          const f = await getFindings(activeScanId);
          setFindings(f);
          setCurrentView('dashboard');
          setDashboardTab('overview');
          loadHistory();
        } else if (scan.status === 'failed' || scan.status === 'cancelled' || scan.status === 'timeout') {
          setIsScanning(false);
          localStorage.removeItem('nshield_active_scan_id');
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
          setErrorMessage(scan.error_message || `Assessment finished with status: ${scan.status}.`);
          loadHistory();
        }
      } catch (err: any) {
        consecutiveFailures++;
        console.error(`Polling error (${consecutiveFailures}/${MAX_CONSECUTIVE_FAILURES}):`, err);
        if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
          setIsScanning(false);
          localStorage.removeItem('nshield_active_scan_id');
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
          setErrorMessage('Lost connection to assessment session. Please verify backend service status.');
        }
      }
    };

    poll();
    pollIntervalRef.current = setInterval(poll, 1200);

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [activeScanId, isScanning]);

  const handleStartScan = async (target: string, authorized: boolean, mode?: string) => {
    setIsFormSubmitting(true);
    setErrorMessage(null);

    try {
      const res = await startScan(target, authorized, mode);

      if (!res || !isValidScanId(res.scanId)) {
        throw new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.');
      }

      const validId = res.scanId.trim();
      localStorage.setItem('nshield_active_scan_id', validId);
      setActiveScanId(validId);
      setIsScanning(true);

      let targetHostname = res.hostname;
      if (!targetHostname) {
        try {
          targetHostname = new URL(res.target).hostname;
        } catch {
          targetHostname = target;
        }
      }

      setCurrentScan({
        id: validId,
        target_url: res.target,
        target_hostname: targetHostname,
        target_scheme: 'https',
        target_port: 443,
        authorized: true,
        mode: res.mode || mode || 'DEFENSIVE / SAFE',
        status: 'queued',
        posture: 'ASSESSED',
        security_score: 100,
        grade: 'A',
        risk_level: 'LOW',
        pages_scanned: 0,
        duration_seconds: 0,
        started_at: new Date().toISOString(),
        findings: [],
      });
      setIsFormSubmitting(false);
    } catch (err: any) {
      // Safe state recovery: do NOT enter fake scanning state
      setIsScanning(false);
      setActiveScanId(null);
      localStorage.removeItem('nshield_active_scan_id');
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      setIsFormSubmitting(false);
      const displayMsg = err?.message || 'Failed to initialize security assessment.';
      setErrorMessage(displayMsg);
      throw err;
    }
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;
    try {
      localStorage.removeItem('nshield_active_scan_id');
      await cancelScan(activeScanId);
      setIsScanning(false);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSelectHistoricalScan = async (scanId: string) => {
    try {
      const scan = await getScan(scanId);
      const f = await getFindings(scanId);
      setCurrentScan(scan);
      setFindings(f);
      setActiveScanId(scanId);
      setIsScanning(false);
      setCurrentView('dashboard');
      setDashboardTab('overview');
    } catch (err: any) {
      console.error('Failed to load past scan:', err);
    }
  };

  const handleCompareScans = async (scanAId: string, scanBId: string) => {
    try {
      const comp = await compareScans(scanAId, scanBId);
      setComparisonData(comp);
    } catch (err: any) {
      console.error('Comparison error:', err);
      alert(`Failed to compare audits: ${err.message}`);
    }
  };

  const handleFindingStatusChange = async (findingId: string, status: FindingStatus) => {
    if (!currentScan) return;
    try {
      await updateFindingStatus(currentScan.id, findingId, status);
      setFindings(prev => prev.map(f => (f.id === findingId ? { ...f, status } : f)));
    } catch (err) {
      console.error('Status update failed:', err);
    }
  };

  const handleInspectFindingById = (findingId: string) => {
    const target = findings.find(f => f.id === findingId);
    if (target) {
      setSelectedFindingForDetail(target);
    }
  };

  return (
    <div className="min-h-screen bg-background text-slate-100 flex flex-col">
      <Header
        currentView={currentView}
        onNavigate={(view) => {
          setCurrentView(view);
          if (view === 'history') loadHistory();
        }}
        hasActiveScan={!!currentScan && currentScan.status === 'completed'}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Scanning in progress view */}
        {isScanning && currentScan ? (
          <ScanProgress
            target={currentScan.target_url}
            progress={currentScan.progress}
            status={currentScan.status}
            mode={currentScan.mode}
            onCancel={handleCancelScan}
          />
        ) : currentView === 'scan' ? (
          <ScanForm
            onStartScan={handleStartScan}
            isLoading={isFormSubmitting}
            error={errorMessage}
          />
        ) : currentView === 'history' ? (
          <ScanHistory
            scans={history}
            onSelectScan={handleSelectHistoricalScan}
            onNewScan={() => setCurrentView('scan')}
            onOpenReport={(scan) => {
              setReportScanTarget(scan);
              setShowReportModal(true);
            }}
            onCompareScans={handleCompareScans}
            onRefreshHistory={loadHistory}
          />
        ) : currentView === 'dashboard' && currentScan ? (
          <div className="space-y-6">
            {/* Dashboard Sub-navigation Tabs */}
            <div className="flex flex-wrap border-b border-border gap-6 text-xs font-mono font-bold uppercase tracking-wider">
              <button
                onClick={() => setDashboardTab('overview')}
                className={`pb-3 px-1 border-b-2 transition cursor-pointer ${
                  dashboardTab === 'overview'
                    ? 'border-primary text-primary glow-yellow-sm'
                    : 'border-transparent text-[#7A7256] hover:text-[#C7B988]'
                }`}
              >
                [01] EXECUTIVE OVERVIEW
              </button>
              <button
                onClick={() => setDashboardTab('findings')}
                className={`pb-3 px-1 border-b-2 transition flex items-center space-x-2 cursor-pointer ${
                  dashboardTab === 'findings'
                    ? 'border-primary text-primary glow-yellow-sm'
                    : 'border-transparent text-[#7A7256] hover:text-[#C7B988]'
                }`}
              >
                <span>[02] VULNERABILITIES &amp; FINDINGS</span>
                <span className="px-2 py-0.2 border border-border bg-[#121212] text-primary text-[10px] font-bold">
                  {findings.length}
                </span>
              </button>
              <button
                onClick={() => setDashboardTab('surface')}
                className={`pb-3 px-1 border-b-2 transition cursor-pointer ${
                  dashboardTab === 'surface'
                    ? 'border-primary text-primary glow-yellow-sm'
                    : 'border-transparent text-[#7A7256] hover:text-[#C7B988]'
                }`}
              >
                [03] ATTACK SURFACE INVENTORY
              </button>
              <button
                onClick={() => setDashboardTab('remediation')}
                className={`pb-3 px-1 border-b-2 transition cursor-pointer ${
                  dashboardTab === 'remediation'
                    ? 'border-primary text-primary glow-yellow-sm'
                    : 'border-transparent text-[#7A7256] hover:text-[#C7B988]'
                }`}
              >
                [04] REMEDIATION CHECKLIST
              </button>
            </div>

            {/* Dashboard Sub-views with ErrorBoundary */}
            <ErrorBoundary fallbackTitle="[ DASHBOARD VIEWPORT EXCEPTION ]">
              {dashboardTab === 'overview' && (
                <DashboardOverview
                  scan={currentScan}
                  findings={findings}
                  onOpenReport={() => {
                    setReportScanTarget(currentScan);
                    setShowReportModal(true);
                  }}
                  onViewFindings={() => setDashboardTab('findings')}
                  onViewSurface={() => setDashboardTab('surface')}
                  onViewRemediation={() => setDashboardTab('remediation')}
                />
              )}

              {dashboardTab === 'findings' && (
                <FindingsList
                  findings={findings}
                  onOpenFindingDetail={(f) => setSelectedFindingForDetail(f)}
                />
              )}

              {dashboardTab === 'surface' && (
                <SurfaceInventoryView
                  inventory={currentScan.inventory}
                  technologies={currentScan.technologies}
                  targetHostname={currentScan.target_hostname}
                />
              )}

              {dashboardTab === 'remediation' && (
                <RemediationChecklist
                  scanId={currentScan.id}
                  onInspectFinding={handleInspectFindingById}
                />
              )}
            </ErrorBoundary>
          </div>
        ) : null}
      </main>

      {/* Report Modal */}
      {showReportModal && (reportScanTarget || currentScan) && (
        <ErrorBoundary fallbackTitle="[ REPORT MODAL EXCEPTION ]">
          <ReportModal
            scan={reportScanTarget || currentScan!}
            onClose={() => {
              setShowReportModal(false);
              setReportScanTarget(null);
            }}
          />
        </ErrorBoundary>
      )}

      {/* Finding Detail Investigation Modal */}
      {selectedFindingForDetail && (
        <FindingDetailModal
          finding={selectedFindingForDetail}
          allFindings={findings}
          scanId={currentScan?.id || ''}
          onClose={() => setSelectedFindingForDetail(null)}
          onStatusChange={handleFindingStatusChange}
        />
      )}

      {/* Scan Comparison Modal */}
      {comparisonData && (
        <ScanComparisonModal
          comparison={comparisonData}
          onClose={() => setComparisonData(null)}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-border py-5 text-center text-[11px] text-[#7A7256] bg-[#030303] font-mono">
        <div className="max-w-7xl mx-auto px-4">
          NayVista Shield &bull; AI-Assisted Web Security Assessment &bull; NayVista Technologies &bull; Strictly Scoped Defensive Engine
        </div>
      </footer>
    </div>
  );
}

export default App;
