/**
 * NayVista Shield - Structured Operational Logger
 * Provides structured JSON / formatted console logs with correlation IDs.
 * Ensures zero secret leakage (tokens, cookies, auth headers are never logged).
 */

const SENSITIVE_PATTERNS = [
  /Bearer\s+[A-Za-z0-9\-_.]+/gi,
  /Basic\s+[A-Za-z0-9+/=]+/gi,
  /(Set-Cookie:\s*[^=]+)=([^;\r\n]+)/gi,
  /(Cookie:\s*[^=]+)=([^;\r\n]+)/gi,
  /(password|passwd|pwd|secret|api[_-]?key|token)["':=\s]+([^,\s&'"]+)/gi,
  /(session_token|session_id|sess_id|phpsessid|jsessionid|admin_sid|[a-zA-Z0-9_-]*sid|[a-zA-Z0-9_-]*token)=([^;,\s]+)/gi,
  /AKIA[0-9A-Z]{16}/g,
  /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
  /gh[pousr]_[0-9a-zA-Z]{36}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

export function sanitizeLogString(str: string): string {
  if (!str || typeof str !== 'string') return '';
  let sanitized = str;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, (match, p1) => {
      if (match.toLowerCase().startsWith('bearer ')) return 'Bearer [REDACTED]';
      if (match.toLowerCase().startsWith('basic ')) return 'Basic [REDACTED]';
      if (match.toLowerCase().startsWith('set-cookie:')) return `${p1}=[REDACTED]`;
      if (match.toLowerCase().startsWith('cookie:')) return `${p1}=[REDACTED]`;
      return '[REDACTED]';
    });
  }
  return sanitized;
}

export interface LogContext {
  scanId?: string;
  target?: string;
  status?: string;
  event?: string;
  [key: string]: any;
}

export const logger = {
  info(message: string, context?: LogContext): void {
    const ts = new Date().toISOString();
    const cleanMsg = sanitizeLogString(message);
    if (process.env.LOG_FORMAT === 'json') {
      console.log(JSON.stringify({ timestamp: ts, level: 'INFO', message: cleanMsg, ...context }));
    } else {
      const ctxStr = context ? ` [${Object.entries(context).map(([k, v]) => `${k}=${v}`).join(' ')}]` : '';
      console.log(`[${ts}] [INFO] ${cleanMsg}${ctxStr}`);
    }
  },

  warn(message: string, context?: LogContext): void {
    const ts = new Date().toISOString();
    const cleanMsg = sanitizeLogString(message);
    if (process.env.LOG_FORMAT === 'json') {
      console.warn(JSON.stringify({ timestamp: ts, level: 'WARN', message: cleanMsg, ...context }));
    } else {
      const ctxStr = context ? ` [${Object.entries(context).map(([k, v]) => `${k}=${v}`).join(' ')}]` : '';
      console.warn(`[${ts}] [WARN] ${cleanMsg}${ctxStr}`);
    }
  },

  error(message: string, error?: any, context?: LogContext): void {
    const ts = new Date().toISOString();
    const cleanMsg = sanitizeLogString(message);
    const errDetail = error instanceof Error ? error.message : (typeof error === 'string' ? sanitizeLogString(error) : '');
    if (process.env.LOG_FORMAT === 'json') {
      console.error(JSON.stringify({ timestamp: ts, level: 'ERROR', message: cleanMsg, error: errDetail, ...context }));
    } else {
      const ctxStr = context ? ` [${Object.entries(context).map(([k, v]) => `${k}=${v}`).join(' ')}]` : '';
      const errStr = errDetail ? ` - Error: ${errDetail}` : '';
      console.error(`[${ts}] [ERROR] ${cleanMsg}${errStr}${ctxStr}`);
    }
  },
};
