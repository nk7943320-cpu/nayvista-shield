import React from 'react';
import { Layers, Server, Code, FileCode } from 'lucide-react';
import { AttackSurface, TechnologySummary } from '../types';

interface SurfaceInventoryViewProps {
  inventory?: AttackSurface;
  technologies?: TechnologySummary;
  targetHostname: string;
}

export const SurfaceInventoryView: React.FC<SurfaceInventoryViewProps> = ({ inventory, technologies, targetHostname }) => {
  return (
    <div className="space-y-5 font-mono">
      {/* Technology Stack Grid */}
      <div className="bg-[#0A0A0A] border border-border p-5 shadow-sm">
        <h3 className="text-xs font-bold uppercase tracking-wider text-primary flex items-center space-x-2 mb-4">
          <Server className="w-4 h-4 text-primary" />
          <span>FINGERPRINTED TECHNOLOGY SIGNATURES</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-[#050505] border border-border p-3.5">
            <div className="text-[10px] font-bold text-[#7A7256] uppercase tracking-wider mb-2">WEB SERVERS</div>
            <div className="flex flex-wrap gap-1.5">
              {technologies?.web_servers && technologies.web_servers.length > 0 ? (
                technologies.web_servers.map((s, i) => (
                  <span key={i} className="px-2 py-0.5 border border-primary/40 bg-[#141205] text-primary text-xs font-bold">
                    {s}
                  </span>
                ))
              ) : (
                <span className="text-xs text-[#5A523A] italic">None fingerprinted</span>
              )}
            </div>
          </div>

          <div className="bg-[#050505] border border-border p-3.5">
            <div className="text-[10px] font-bold text-[#7A7256] uppercase tracking-wider mb-2">BACKEND RUNTIMES</div>
            <div className="flex flex-wrap gap-1.5">
              {technologies?.backend && technologies.backend.length > 0 ? (
                technologies.backend.map((b, i) => (
                  <span key={i} className="px-2 py-0.5 border border-primary/40 bg-[#141205] text-primary text-xs font-bold">
                    {b}
                  </span>
                ))
              ) : (
                <span className="text-xs text-[#5A523A] italic">None fingerprinted</span>
              )}
            </div>
          </div>

          <div className="bg-[#050505] border border-border p-3.5">
            <div className="text-[10px] font-bold text-[#7A7256] uppercase tracking-wider mb-2">CMS / PLATFORMS</div>
            <div className="flex flex-wrap gap-1.5">
              {technologies?.cms && technologies.cms.length > 0 ? (
                technologies.cms.map((c, i) => (
                  <span key={i} className="px-2 py-0.5 border border-primary/40 bg-[#141205] text-primary text-xs font-bold">
                    {c}
                  </span>
                ))
              ) : (
                <span className="text-xs text-[#5A523A] italic">None fingerprinted</span>
              )}
            </div>
          </div>

          <div className="bg-[#050505] border border-border p-3.5">
            <div className="text-[10px] font-bold text-[#7A7256] uppercase tracking-wider mb-2">FRONTEND &amp; LIBS</div>
            <div className="flex flex-wrap gap-1.5">
              {[...(technologies?.frontend || []), ...(technologies?.libraries || [])].length > 0 ? (
                [...(technologies?.frontend || []), ...(technologies?.libraries || [])].map((f, i) => (
                  <span key={i} className="px-2 py-0.5 border border-[#3D3310] bg-[#121212] text-[#FFF8DB] text-xs font-bold">
                    {f}
                  </span>
                ))
              ) : (
                <span className="text-xs text-[#5A523A] italic">None fingerprinted</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Discovered Endpoints and Input Parameters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Endpoints */}
        <div className="bg-[#0A0A0A] border border-border p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-primary flex items-center space-x-2 uppercase tracking-wider">
              <Layers className="w-4 h-4 text-primary" />
              <span>SAME-ORIGIN ENDPOINTS ({inventory?.endpoints?.length ?? 0})</span>
            </h3>
            <span className="text-[11px] text-[#7A7256] font-mono">{targetHostname}</span>
          </div>

          <div className="bg-[#030303] border border-border max-h-64 overflow-y-auto p-2 text-xs text-[#FFF8DB] space-y-1">
            {inventory?.endpoints && inventory.endpoints.length > 0 ? (
              inventory.endpoints.map((ep, i) => (
                <div key={i} className="flex items-center space-x-2 hover:bg-[#121212] px-2 py-1 transition">
                  <span className="text-primary font-bold">GET</span>
                  <span className="truncate text-[#C7B988]">{ep}</span>
                </div>
              ))
            ) : (
              <div className="text-[#5A523A] italic p-2">No endpoints cataloged</div>
            )}
          </div>
        </div>

        {/* Input Parameters */}
        <div className="bg-[#0A0A0A] border border-border p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-primary flex items-center space-x-2 uppercase tracking-wider">
              <Code className="w-4 h-4 text-primary" />
              <span>DYNAMIC PARAMETERS ({inventory?.parameters?.length ?? 0})</span>
            </h3>
            <span className="text-[10px] text-[#7A7256] uppercase font-bold">INPUT VECTOR</span>
          </div>

          <div className="bg-[#030303] border border-border max-h-64 overflow-y-auto p-3 text-xs text-[#FFF8DB]">
            {inventory?.parameters && inventory.parameters.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {inventory.parameters.map((param, i) => (
                  <span key={i} className="px-2 py-1 bg-[#121212] border border-[#26200A] text-primary font-bold">
                    {param}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-[#5A523A] italic p-2">No dynamic parameters observed</div>
            )}
          </div>
        </div>
      </div>

      {/* Discovered Forms */}
      <div className="bg-[#0A0A0A] border border-border p-5 shadow-sm">
        <h3 className="text-xs font-bold uppercase tracking-wider text-primary flex items-center space-x-2 mb-3">
          <FileCode className="w-4 h-4 text-primary" />
          <span>AUDITED FORMS ({inventory?.forms?.length ?? 0})</span>
        </h3>

        {inventory?.forms && inventory.forms.length > 0 ? (
          <div className="space-y-2.5">
            {inventory.forms.map((form, i) => (
              <div key={i} className="bg-[#030303] border border-border p-3.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 bg-primary text-black font-extrabold uppercase">
                      {form.method}
                    </span>
                    <span className="text-[#FFF8DB] font-bold">{form.action}</span>
                  </div>
                  <span className="text-[#7A7256] text-[11px] truncate">&gt; {form.page_url}</span>
                </div>

                <div className="flex flex-wrap gap-1.5 pt-2 border-t border-border">
                  <span className="text-[#7A7256] text-[11px] mr-1">FIELDS:</span>
                  {(form.fields || []).map((f, j) => (
                    <span key={j} className="px-2 py-0.5 bg-[#0D0D0D] border border-border text-[#C7B988]">
                      {f.name} <span className="text-[#7A7256]">({f.type})</span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[#5A523A] italic">No HTML forms discovered across scanned pages.</p>
        )}
      </div>
    </div>
  );
};
