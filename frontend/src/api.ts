import {
  ScanRecord,
  Finding,
  ScanComparison,
  TargetHistoryGroup,
  RemediationItem,
  FindingStatus,
  RemediationState,
} from './types';

const API_BASE = (import.meta.env.VITE_API_URL ? String(import.meta.env.VITE_API_URL).replace(/\/+$/, '') : '') + '/api';

function getHeaders(customHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = {
    ...customHeaders,
  };
  const token = localStorage.getItem('nshield_auth_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const tenantId = localStorage.getItem('nshield_tenant_id');
  if (tenantId) {
    headers['X-Tenant-ID'] = tenantId;
  }
  return headers;
}

/**
 * Centralized safe fetch abstraction.
 * Defensively handles network errors, empty responses, non-JSON/HTML payloads,
 * malformed JSON, and structured HTTP error contracts.
 */
export async function safeFetch<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(input, init);
  } catch (_networkErr: any) {
    const err = new Error(
      'Unable to connect to NayVista Shield API service. Please verify your network connection and backend server status.'
    );
    (err as any).category = 'PLATFORM_FAILURE';
    (err as any).code = 'BACKEND_UNAVAILABLE';
    throw err;
  }

  // Read response body text safely
  let rawText = '';
  try {
    rawText = await response.text();
  } catch {
    rawText = '';
  }

  const trimmed = rawText.trim();
  const contentType = (response.headers.get('content-type') || '').toLowerCase();

  // Handle 204 No Content
  if (response.status === 204) {
    return { success: true } as unknown as T;
  }

  // Handle empty / whitespace-only response bodies
  if (!trimmed) {
    const err = new Error(
      !response.ok
        ? `ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response (HTTP ${response.status}).`
        : 'ASSESSMENT INITIALIZATION FAILED: The assessment service returned an empty response.'
    );
    (err as any).category = 'PLATFORM_FAILURE';
    (err as any).code = 'EMPTY_RESPONSE';
    throw err;
  }

  // Handle HTML responses (e.g. text/html, 502/504 Bad Gateway default HTML error pages)
  if (contentType.includes('text/html') || trimmed.startsWith('<!DOCTYPE') || (trimmed.startsWith('<html') && trimmed.endsWith('>'))) {
    const err = new Error(
      `ASSESSMENT INITIALIZATION FAILED: The assessment service returned a non-JSON response (HTTP ${response.status}). The server or proxy may be unavailable.`
    );
    (err as any).category = 'PLATFORM_FAILURE';
    (err as any).code = 'PROXY_OR_SERVER_ERROR';
    throw err;
  }

  // Safely parse JSON
  let parsed: any;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    const err = new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned malformed JSON.');
    (err as any).category = 'PLATFORM_FAILURE';
    (err as any).code = 'MALFORMED_JSON';
    throw err;
  }

  // Handle non-2xx HTTP responses
  if (!response.ok) {
    const errorMsg =
      parsed?.error ||
      parsed?.message ||
      `Request failed with HTTP ${response.status}${response.statusText ? ' ' + response.statusText : ''}`;
    const err = new Error(errorMsg);
    (err as any).code = parsed?.error_details?.code || parsed?.code || (response.status >= 500 ? 'PLATFORM_ERROR' : 'VALIDATION_ERROR');
    (err as any).category = parsed?.error_details?.category || parsed?.category || (response.status >= 500 ? 'PLATFORM_FAILURE' : 'ASSESSMENT_LIMITATION');
    if (parsed?.error_details?.retryable !== undefined) {
      (err as any).retryable = parsed.error_details.retryable;
    }
    throw err;
  }

  return parsed as T;
}

export async function startScan(
  target: string,
  authorized: boolean,
  mode: string = 'DEFENSIVE / SAFE'
): Promise<{ success: boolean; scanId: string; target: string; hostname?: string; mode?: string; error?: string }> {
  const data = await safeFetch<any>(
    `${API_BASE}/scans`,
    {
      method: 'POST',
      headers: getHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ target, authorized, mode }),
    }
  );

  const scanId = data?.scanId || data?.data?.scanId;

  // Strict scanId validation: reject null, undefined, "", "undefined", "null"
  if (
    !scanId ||
    typeof scanId !== 'string' ||
    scanId.trim().length === 0 ||
    scanId === 'undefined' ||
    scanId === 'null'
  ) {
    throw new Error('ASSESSMENT INITIALIZATION FAILED: The assessment service returned an invalid scan identifier.');
  }

  return {
    ...data,
    scanId,
    mode: data.mode || data?.data?.mode || mode,
  };
}

export async function getScan(id: string): Promise<ScanRecord> {
  const data = await safeFetch<{ success: boolean; scan: ScanRecord; error?: string }>(`${API_BASE}/scans/${id}`, {
    headers: getHeaders(),
  });
  if (!data || !data.scan) {
    throw new Error('Failed to fetch scan details: Scan record missing from response.');
  }
  return data.scan;
}

export async function getFindings(id: string, filters?: { severity?: string; category?: string; status?: string }): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.category) params.set('category', filters.category);
  if (filters?.status) params.set('status', filters.status);

  const data = await safeFetch<{ success: boolean; findings: Finding[]; error?: string }>(
    `${API_BASE}/scans/${id}/findings?${params.toString()}`,
    {
      headers: getHeaders(),
    }
  );
  return data?.findings || [];
}

export async function updateFindingStatus(scanId: string, findingId: string, status: FindingStatus): Promise<boolean> {
  const data = await safeFetch<{ success: boolean; error?: string }>(
    `${API_BASE}/scans/${scanId}/findings/${findingId}`,
    {
      method: 'PATCH',
      headers: getHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ status }),
    }
  );
  return !!data?.success;
}

export async function getScanHistory(page: number = 1, limit: number = 50): Promise<{ scans: ScanRecord[]; total: number }> {
  const data = await safeFetch<{ success: boolean; scans: ScanRecord[]; total: number; error?: string }>(
    `${API_BASE}/scans?page=${page}&limit=${limit}`,
    {
      headers: getHeaders(),
    }
  );
  return {
    scans: data?.scans || [],
    total: data?.total || (data?.scans || []).length,
  };
}

export async function deleteScan(id: string): Promise<boolean> {
  const data = await safeFetch<{ success: boolean; error?: string }>(`${API_BASE}/scans/${id}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
  return !!data?.success;
}

export async function compareScans(baseScanId: string, targetScanId: string): Promise<ScanComparison> {
  const data = await safeFetch<{ success: boolean; comparison: ScanComparison; error?: string }>(
    `${API_BASE}/scans/${baseScanId}/compare/${targetScanId}`,
    {
      headers: getHeaders(),
    }
  );
  return data.comparison;
}

export async function getTargetHistory(): Promise<TargetHistoryGroup[]> {
  const data = await safeFetch<{ success: boolean; targets: TargetHistoryGroup[]; error?: string }>(
    `${API_BASE}/scans/targets/history`,
    {
      headers: getHeaders(),
    }
  );
  return data?.targets || [];
}

export async function getRemediationItems(scanId: string): Promise<RemediationItem[]> {
  const data = await safeFetch<{ success: boolean; items: RemediationItem[]; error?: string }>(
    `${API_BASE}/scans/${scanId}/remediation`,
    {
      headers: getHeaders(),
    }
  );
  return data?.items || [];
}

export async function updateRemediationItem(scanId: string, findingId: string, state: RemediationState): Promise<RemediationItem> {
  const data = await safeFetch<{ success: boolean; item: RemediationItem; error?: string }>(
    `${API_BASE}/scans/${scanId}/remediation/${findingId}`,
    {
      method: 'PUT',
      headers: getHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ state }),
    }
  );
  return data.item;
}

export async function cancelScan(id: string): Promise<boolean> {
  const data = await safeFetch<{ success: boolean; error?: string }>(`${API_BASE}/scans/${id}/cancel`, {
    method: 'POST',
    headers: getHeaders(),
  });
  return !!data?.success;
}

export function getReportDownloadUrl(id: string, format: 'json' | 'html'): string {
  return `${API_BASE}/scans/${id}/report?format=${format}`;
}
