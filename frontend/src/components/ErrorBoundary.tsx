import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });
    console.error('[NayVista Shield UI ErrorBoundary caught an exception]:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 font-mono">
          <div className="bg-[#0A0A0A] border-2 border-amber-500/60 p-6 max-w-2xl w-full shadow-2xl space-y-4">
            <div className="flex items-center space-x-3 text-amber-400 border-b border-amber-500/30 pb-3">
              <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0" />
              <div>
                <div className="text-xs font-bold uppercase tracking-widest text-amber-500">
                  NAYVISTA SHIELD // RUNTIME RECOVERY
                </div>
                <h2 className="text-base font-extrabold text-[#FFF8DB]">
                  {this.props.fallbackTitle || '[ REPORT VIEWPORT RENDER EXCEPTION ]'}
                </h2>
              </div>
            </div>

            <div className="text-xs text-[#D4C9A8] space-y-2">
              <p>
                An unexpected UI rendering anomaly was intercepted while displaying assessment data.
                Shield safety controls prevented the application from terminating.
              </p>
              {this.state.error && (
                <div className="bg-[#030303] border border-amber-500/20 p-3 text-[11px] text-amber-300 font-mono overflow-x-auto whitespace-pre-wrap">
                  {this.state.error.name}: {this.state.error.message}
                </div>
              )}
            </div>

            <div className="pt-2 flex flex-wrap gap-3">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 bg-primary hover:bg-[#FFE033] text-black font-bold text-xs uppercase tracking-wider flex items-center space-x-2 transition cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>RETRY RENDER</span>
              </button>
              <button
                onClick={() => {
                  this.handleReset();
                  window.location.reload();
                }}
                className="px-4 py-2 bg-[#121212] hover:bg-[#1C1805] text-[#FFF8DB] hover:text-primary border border-border hover:border-primary font-bold text-xs uppercase tracking-wider flex items-center space-x-2 transition cursor-pointer"
              >
                <Home className="w-3.5 h-3.5" />
                <span>RELOAD APPLICATION</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
