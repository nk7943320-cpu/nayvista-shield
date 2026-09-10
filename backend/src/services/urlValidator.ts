import dns from 'dns';
import { URL } from 'url';
import { config } from '../config.js';
import { ErrorCategory } from '../types/index.js';

export interface ValidatedTarget {
  url: string;
  hostname: string;
  scheme: string;
  port: number;
}

export class ValidationError extends Error {
  code: string;
  category: ErrorCategory;
  retryable: boolean;
  constructor(message: string, code: string = 'INVALID_TARGET', category: ErrorCategory = 'PLATFORM_FAILURE', retryable: boolean = false) {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
    this.category = category;
    this.retryable = retryable;
  }
}

function isPrivateOrReservedIP(rawIp: string): boolean {
  const ip = rawIp.toLowerCase().trim();

  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (ip.startsWith('::ffff:')) {
    const unmapped = ip.replace('::ffff:', '');
    return isPrivateOrReservedIP(unmapped);
  }

  // IPv4 checks
  if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip === '169.254.169.254') return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true;

  // 172.16.0.0 - 172.31.255.255
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }

  // IPv6 checks
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) {
    return true;
  }

  return false;
}

export async function validateTargetUrl(rawUrl: string, authorized: boolean): Promise<ValidatedTarget> {
  if (!authorized) {
    throw new ValidationError('Security testing must be explicitly authorized. Please confirm authorization.', 'UNAUTHORIZED_TARGET', 'PLATFORM_FAILURE');
  }

  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new ValidationError('A target URL must be specified.', 'MISSING_TARGET', 'PLATFORM_FAILURE');
  }

  if (rawUrl.length > 2048) {
    throw new ValidationError('Target URL exceeds maximum permitted length (2048 characters).', 'URL_TOO_LONG', 'PLATFORM_FAILURE');
  }

  // Reject shell metacharacters and control characters
  if (/[\r\n\0`$;|&<>]/.test(rawUrl)) {
    throw new ValidationError('Invalid target URL: Control or shell metacharacters are strictly prohibited.', 'MALFORMED_URL', 'PLATFORM_FAILURE');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new ValidationError('Invalid target URL format. Must include scheme, e.g. https://example.com', 'INVALID_TARGET_URL', 'PLATFORM_FAILURE');
  }

  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    throw new ValidationError(`Unsupported scheme '${scheme}'. Only HTTP and HTTPS are permitted.`, 'UNSUPPORTED_SCHEME', 'PLATFORM_FAILURE');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    throw new ValidationError('Target URL must include a valid hostname.', 'MISSING_HOSTNAME', 'PLATFORM_FAILURE');
  }

  const port = parsed.port ? parseInt(parsed.port, 10) : (scheme === 'https' ? 443 : 80);

  // Unconditional Cloud Metadata Protection (strictly prohibited under all configurations)
  if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal' || hostname === 'instance-data') {
    throw new ValidationError(`SSRF Protection: Access to cloud metadata endpoint '${hostname}' is strictly prohibited.`, 'SSRF_BLOCKED', 'PLATFORM_FAILURE');
  }

  // SSRF Protection for local / private networks
  if (!config.allowLocalTargets) {
    const bannedHostnames = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
    if (bannedHostnames.includes(hostname) || hostname.endsWith('.localhost')) {
      throw new ValidationError(`SSRF Protection: Access to '${hostname}' is prohibited.`, 'SSRF_BLOCKED', 'PLATFORM_FAILURE');
    }

    if (isPrivateOrReservedIP(hostname)) {
      throw new ValidationError(`SSRF Protection: Private or reserved IP '${hostname}' is prohibited.`, 'SSRF_BLOCKED', 'PLATFORM_FAILURE');
    }

    // Resolve DNS to verify resolved addresses against SSRF
    try {
      const lookupResult = await dns.promises.lookup(hostname, { all: true });
      for (const entry of lookupResult) {
        if (isPrivateOrReservedIP(entry.address)) {
          throw new ValidationError(`SSRF Protection: Hostname '${hostname}' resolves to private address '${entry.address}'.`, 'SSRF_BLOCKED', 'PLATFORM_FAILURE');
        }
      }
    } catch (err: any) {
      if (err instanceof ValidationError) throw err;
      // If DNS resolution fails during initial syntax/SSRF validation, permit the target
      // to proceed to the scanner engine so the 14-stage pipeline can gracefully record
      // DNS Resolution: FAILED and handle target limitations without crashing the platform.
    }
  }

  // Clean trailing slash for path if not root
  const cleanedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}${parsed.search}`;

  return {
    url: cleanedUrl || `${parsed.protocol}//${parsed.host}/`,
    hostname,
    scheme,
    port,
  };
}
