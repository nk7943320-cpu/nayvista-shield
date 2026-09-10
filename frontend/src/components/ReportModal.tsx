import React from 'react';
import { X, Download, Printer, ExternalLink, Terminal } from 'lucide-react';
import { ScanRecord } from '../types';
import { getReportDownloadUrl } from '../api';

interface ReportModalProps {
  scan: ScanRecord;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ scan, onClose }) => {
  const jsonUrl = getReportDownloadUrl(scan.id, 'json');
  const htmlUrl = getReportDownloadUrl(scan.id, 'html');

  const handleDownloadJson = async () => {
    try {
      const res = await fetch(jsonUrl);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nayvista-shield-${scan.target_hostname}-${scan.id.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Download error:', e);
    }
  };

  const handleOpenPrintableHtml = () => {
    window.open(htmlUrl, '_blank');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm font-mono">
      <div className="bg-[#0A0A0A] border-2 border-primary/50 w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-border flex items-center justify-between bg-[#050505]">
          <div>
            <div className="flex items-center space-x-2 text-primary text-xs font-bold uppercase tracking-widest mb-1">
              <Terminal className="w-3.5 h-3.5" />
              <span>REPORT GENERATOR // COMPLIANCE ARTIFACT</span>
            </div>
            <h3 className="text-base font-bold text-[#FFF8DB]">
              {scan.target_hostname} &bull; {scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : 'SCORE: N/A'} (GRADE {scan.grade || 'N/A'})
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-[#A89F82] hover:text-primary transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5 overflow-y-auto text-xs">
          <div className="bg-[#030303] border border-border p-4">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary mb-1.5">
              EXECUTIVE ASSESSMENT SUMMARY
            </h4>
            <p className="text-[#D4C9A8] leading-relaxed">
              {scan.ai_analysis?.executive_summary || 'Security assessment concluded.'}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-[#050505] border border-border p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="font-bold text-primary text-xs uppercase mb-1 flex items-center space-x-1.5">
                  <Printer className="w-3.5 h-3.5" />
                  <span>PRINTABLE HTML / PDF</span>
                </div>
                <p className="text-[11px] text-[#A89F82] leading-relaxed">
                  Standalone formatted audit report with Black × Yellow styling and print stylesheet for PDF client delivery.
                </p>
              </div>
              <button
                onClick={handleOpenPrintableHtml}
                className="w-full py-2 px-3 bg-primary hover:bg-[#FFE033] text-black font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 transition cursor-pointer"
              >
                <span>OPEN REPORT</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="bg-[#050505] border border-border p-4 flex flex-col justify-between space-y-3">
              <div>
                <div className="font-bold text-primary text-xs uppercase mb-1 flex items-center space-x-1.5">
                  <Download className="w-3.5 h-3.5" />
                  <span>MACHINE-READABLE JSON</span>
                </div>
                <p className="text-[11px] text-[#A89F82] leading-relaxed">
                  Raw findings, OWASP taxonomy, sanitized evidence, and inventory metrics for CI/CD or SIEM ingestion.
                </p>
              </div>
              <button
                onClick={handleDownloadJson}
                className="w-full py-2 px-3 bg-[#121212] hover:bg-[#1C1805] text-[#FFF8DB] hover:text-primary border border-border hover:border-primary font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 transition cursor-pointer"
              >
                <span>DOWNLOAD JSON</span>
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-[#030303] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-[#121212] text-[#A89F82] hover:text-[#FFF8DB] border border-border text-xs font-bold uppercase tracking-wider cursor-pointer transition"
          >
            [CLOSE WINDOW]
          </button>
        </div>
      </div>
    </div>
  );
};
