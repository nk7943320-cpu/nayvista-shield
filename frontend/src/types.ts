export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';
export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timeout';
export type FindingStatus = 'OPEN' | 'RESOLVED' | 'RECURRED' | 'ACCEPTED_RISK';
export type RemediationState = 'OPEN' | 'IN_PROGRESS' | 'COMPLETED';

export interface Finding {
  id: string;
  scanner: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status?: FindingStatus;
  category: string;
  owasp: string;
  cwe?: string;
  url: string;
  affected_component?: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  references?: string[];
  first_seen?: string;
  firstSeen?: string;
  scan_id?: string;
  scanId?: string;
  tenant_id?: string;
  affected_urls: string[];
  structured_evidence?: {
    test: string;
    target: string;
    endpoint: string;
    expected: string;
    observed: string;
    evidence: string;
    confidence: string;
  };
}

export interface AttackSurface {
  total_pages: number;
  endpoints: string[];
  parameters: string[];
  forms_count: number;
  forms: Array<{
    page_url: string;
    action: string;
    method: string;
    fields: Array<{ name: string; type: string }>;
  }>;
  api_endpoints: string[];
}

export interface TechnologySummary {
  web_servers: string[];
  backend: string[];
  cms: string[];
  frontend: string[];
  libraries: string[];
}

export interface ProgressStep {
  phase: string;
  message: string;
  step: number;
  total_steps: number;
  timestamp: number;
  stats?: Record<string, any>;
}

export interface AIAnalysis {
  provider: string;
  executive_summary: string;
  risk_narrative: string;
  remediation_roadmap: Array<{
    priority: number;
    title: string;
    action: string;
    target: string;
  }>;
}

export interface NetworkPortExposure {
  port: number;
  service: string;
  state: 'OPEN' | 'CLOSED' | 'FILTERED';
  exposure: string;
  risk: string;
}

export interface DnsResolutionInfo {
  status: string;
  ipv4: string;
  ipv6: string;
  all_ips: string[];
}

export type ErrorCategory = 'PLATFORM_FAILURE' | 'ASSESSMENT_LIMITATION' | 'SECURITY_FINDING';

export interface AssessmentCoverage {
  completed_stages: number;
  total_stages: number;
  coverage_pct?: number;
  percentage?: number;
  assessment_scope?: string;
  status?: string;
}

export interface AssessmentLimitation {
  stage: string;
  status?: string;
  code?: string;
  category?: ErrorCategory;
  reason?: string;
  description?: string;
}

export interface ScanRecord {
  id: string;
  target_url: string;
  target_hostname: string;
  target_scheme: string;
  target_port: number;
  authorized: boolean;
  status: ScanStatus;
  assessment_status?: 'COMPLETED' | 'COMPLETED_WITH_LIMITATIONS' | 'FAILED' | 'CANCELLED';
  is_limited?: boolean;
  mode?: string;
  resolved_ip?: string;
  dns?: DnsResolutionInfo;
  network_exposure?: NetworkPortExposure[];
  coverage?: AssessmentCoverage;
  stage_status?: Record<string, 'PENDING' | 'RUNNING' | 'COMPLETED' | 'SKIPPED' | 'LIMITED' | 'FAILED'>;
  limitations?: AssessmentLimitation[];
  posture?: string;
  security_score: number | null;
  grade: string;
  risk_level: string;
  pages_scanned: number;
  duration_seconds: number;
  started_at: string;
  completed_at?: string;
  error_message?: string;
  error_code?: string;
  error_category?: ErrorCategory;
  progress?: ProgressStep;
  tenant_id?: string;
  findings: Finding[];
  inventory?: AttackSurface;
  technologies?: TechnologySummary;
  ai_analysis?: AIAnalysis;
}

export interface ScanComparison {
  base_scan: ScanRecord;
  target_scan: ScanRecord;
  delta: {
    score: number;
    grade_changed: boolean;
    risk_changed: boolean;
    posture_changed: boolean;
    severity_diff: Record<Severity, number>;
    attack_surface_diff: {
      pages: number;
      endpoints: number;
      forms: number;
      parameters: number;
    };
  };
  findings: {
    new: Finding[];
    resolved: Finding[];
    persistent: Finding[];
    regressed: Finding[];
  };
  summary: {
    new_count: number;
    resolved_count: number;
    persistent_count: number;
    regressed_count: number;
  };
}

export interface TargetHistoryGroup {
  normalized_target: string;
  target_hostname: string;
  target_port: number;
  target_scheme: string;
  scan_count: number;
  latest_score: number | null;
  latest_grade: string;
  latest_risk: string;
  latest_posture: string;
  latest_scan_id: string;
  scans: Array<{
    id: string;
    started_at: string;
    security_score: number | null;
    grade: string;
    risk_level: string;
    posture: string;
    findings_count: number;
    duration_seconds: number;
    status: ScanStatus;
  }>;
}

export interface RemediationItem {
  id: string;
  finding_id: string;
  title: string;
  severity: Severity;
  category: string;
  component: string;
  action: string;
  state: RemediationState;
  updated_at: string;
}
