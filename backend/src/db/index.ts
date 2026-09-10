import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config.js';
import {
  ScanRecord,
  Finding,
  AttackSurface,
  TechnologySummary,
  AIAnalysis,
  FindingStatus,
  TargetHistoryGroup,
  RemediationItem,
  RemediationState,
} from '../types/index.js';
import { sanitizeLogString } from '../utils/logger.js';

export function normalizeTargetOrigin(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    const port = u.port ? `:${u.port}` : (u.protocol === 'https:' ? ':443' : ':80');
    return `${u.protocol}//${u.hostname.toLowerCase()}${port}`;
  } catch {
    return rawUrl.trim().toLowerCase();
  }
}

class MemoryStorage {
  scans: Map<string, ScanRecord> = new Map();
  findingsMap: Map<string, Finding[]> = new Map();
  remediations: Map<string, RemediationItem> = new Map();
  auditLogs: Array<any> = [];

  saveScan(scan: ScanRecord) {
    const tenantId = scan.tenant_id || 'default';
    this.scans.set(scan.id, { ...scan, tenant_id: tenantId });
  }

  updateScan(id: string, updates: Partial<ScanRecord>) {
    const existing = this.scans.get(id);
    if (existing) {
      const findingsToKeep = (updates.findings && updates.findings.length > 0)
        ? updates.findings
        : (this.findingsMap.get(id) || existing.findings || []);

      this.scans.set(id, { ...existing, ...updates, findings: findingsToKeep });
    }
  }

  getScan(id: string, tenantId?: string): ScanRecord | null {
    const scan = this.scans.get(id);
    if (!scan) return null;
    if (tenantId && tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId) {
      return null; // Enforce tenant isolation
    }
    const cloned = JSON.parse(JSON.stringify(scan));
    cloned.findings = this.findingsMap.get(id) || cloned.findings || [];
    return cloned;
  }

  listScans(tenantId?: string, limit: number = 50, offset: number = 0): { scans: ScanRecord[]; total: number } {
    const all = Array.from(this.scans.values())
      .filter(s => !tenantId || tenantId === '*' || (s.tenant_id || 'default') === tenantId)
      .map(s => ({
        ...s,
        findings: this.findingsMap.get(s.id) || s.findings || [],
      }))
      .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());

    return {
      scans: all.slice(offset, offset + limit),
      total: all.length,
    };
  }

  deleteScan(id: string, tenantId: string = 'default'): boolean {
    const scan = this.scans.get(id);
    if (!scan) return false;
    if (tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId) {
      return false; // Cross-tenant delete blocked
    }
    this.scans.delete(id);
    this.findingsMap.delete(id);
    return true;
  }

  saveFindings(scanId: string, findings: Finding[], tenantId: string = 'default') {
    const sanitized = findings.map(f => ({
      ...f,
      tenant_id: tenantId,
      status: f.status || 'OPEN',
      evidence: sanitizeLogString(f.evidence || ''),
    }));
    this.findingsMap.set(scanId, sanitized);
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.findings = sanitized;
    }
  }

  getFindings(scanId: string, tenantId?: string): Finding[] {
    const scan = this.scans.get(scanId);
    if (scan && tenantId && tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId) {
      return [];
    }
    return this.findingsMap.get(scanId) || [];
  }

  updateFindingStatus(scanId: string, findingId: string, status: FindingStatus, tenantId: string = 'default'): boolean {
    const scan = this.scans.get(scanId);
    if (!scan || (tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId)) {
      return false;
    }
    const findings = this.findingsMap.get(scanId) || [];
    const targetFinding = findings.find(f => f.id === findingId);
    if (targetFinding) {
      targetFinding.status = status;
      return true;
    }
    return false;
  }

  getTargetHistory(tenantId?: string): TargetHistoryGroup[] {
    const { scans } = this.listScans(tenantId, 500, 0);
    const groups = new Map<string, ScanRecord[]>();

    for (const scan of scans) {
      const origin = normalizeTargetOrigin(scan.target_url);
      if (!groups.has(origin)) {
        groups.set(origin, []);
      }
      groups.get(origin)!.push(scan);
    }

    const result: TargetHistoryGroup[] = [];
    for (const [origin, scanList] of groups.entries()) {
      const sorted = scanList.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
      const latest = sorted[0];

      result.push({
        normalized_target: origin,
        target_hostname: latest.target_hostname,
        target_port: latest.target_port,
        target_scheme: latest.target_scheme,
        scan_count: sorted.length,
        latest_score: latest.security_score,
        latest_grade: latest.grade,
        latest_risk: latest.risk_level,
        latest_posture: latest.posture || 'ASSESSED',
        latest_scan_id: latest.id,
        scans: sorted.map(s => ({
          id: s.id,
          started_at: s.started_at,
          security_score: s.security_score,
          grade: s.grade,
          risk_level: s.risk_level,
          posture: s.posture || 'ASSESSED',
          findings_count: (this.findingsMap.get(s.id) || s.findings || []).length,
          duration_seconds: s.duration_seconds,
          status: s.status,
        })),
      });
    }

    return result.sort((a, b) => (b.latest_score ?? 0) - (a.latest_score ?? 0));
  }

  getRemediationItems(scanId: string, tenantId?: string): RemediationItem[] {
    const scan = this.scans.get(scanId);
    if (scan && tenantId && tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId) {
      return [];
    }
    const findings = this.findingsMap.get(scanId) || [];
    return findings.map(f => {
      const key = `${scanId}:${f.id}`;
      const existing = this.remediations.get(key);
      return existing || {
        id: uuidv4(),
        finding_id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        component: f.affected_component || f.scanner,
        action: f.remediation,
        state: 'OPEN' as RemediationState,
        updated_at: new Date().toISOString(),
      };
    });
  }

  saveRemediationItem(scanId: string, findingId: string, state: RemediationState, tenantId: string = 'default'): RemediationItem | null {
    const scan = this.scans.get(scanId);
    if (!scan || (tenantId !== '*' && (scan.tenant_id || 'default') !== tenantId)) {
      return null;
    }
    const findings = this.findingsMap.get(scanId) || [];
    const finding = findings.find(f => f.id === findingId);
    if (!finding) return null;

    const key = `${scanId}:${findingId}`;
    const item: RemediationItem = {
      id: uuidv4(),
      finding_id: findingId,
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      component: finding.affected_component || finding.scanner,
      action: finding.remediation,
      state,
      updated_at: new Date().toISOString(),
    };
    this.remediations.set(key, item);
    return item;
  }

  saveAttackSurface(scanId: string, inventory: AttackSurface, technologies: TechnologySummary) {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.inventory = inventory;
      scan.technologies = technologies;
    }
  }

  saveAIAnalysis(scanId: string, analysis: AIAnalysis) {
    const scan = this.scans.get(scanId);
    if (scan) {
      scan.ai_analysis = analysis;
    }
  }

  logAudit(scanId: string | null, targetUrl: string, action: string, details: any = {}) {
    this.auditLogs.push({
      id: uuidv4(),
      scanId,
      targetUrl,
      action,
      timestamp: new Date().toISOString(),
      details,
    });
  }
}

class DatabaseAdapter {
  private pool: Pool | null = null;
  private memory = new MemoryStorage();
  public isPostgres = false;

  async init(): Promise<void> {
    if (config.databaseUrl) {
      try {
        this.pool = new Pool({ connectionString: config.databaseUrl, connectionTimeoutMillis: 3000 });
        const client = await this.pool.connect();
        try {
          await this.runMigrations(client);
        } finally {
          client.release();
        }
        this.isPostgres = true;
        console.log('[Database] Connected to PostgreSQL and verified schema tables successfully.');
      } catch (err: any) {
        console.warn(`[Database] PostgreSQL connection failed (${err.message}). Falling back to local memory store.`);
        this.pool = null;
        this.isPostgres = false;
      }
    } else {
      console.log('[Database] No DATABASE_URL specified. Running with local memory store.');
    }
  }

  private async runMigrations(client: any): Promise<void> {
    await client.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id VARCHAR(64) PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        target_url TEXT NOT NULL,
        target_hostname VARCHAR(255) NOT NULL,
        target_scheme VARCHAR(10) NOT NULL,
        target_port INTEGER NOT NULL,
        authorized BOOLEAN NOT NULL DEFAULT FALSE,
        status VARCHAR(32) NOT NULL DEFAULT 'pending',
        posture VARCHAR(32) DEFAULT 'ASSESSED',
        security_score INTEGER DEFAULT 100,
        grade VARCHAR(5) DEFAULT 'A',
        risk_level VARCHAR(32) DEFAULT 'LOW',
        pages_scanned INTEGER DEFAULT 0,
        duration_seconds NUMERIC(8, 2) DEFAULT 0,
        started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP WITH TIME ZONE,
        error_message TEXT
      );

      ALTER TABLE scans ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';
      ALTER TABLE scans ADD COLUMN IF NOT EXISTS posture VARCHAR(32) DEFAULT 'ASSESSED';

      CREATE TABLE IF NOT EXISTS findings (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        scanner VARCHAR(64) NOT NULL,
        title VARCHAR(255) NOT NULL,
        severity VARCHAR(32) NOT NULL,
        confidence VARCHAR(32) NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
        category VARCHAR(128) NOT NULL,
        owasp VARCHAR(128) NOT NULL,
        cwe VARCHAR(32),
        affected_component VARCHAR(255),
        url TEXT NOT NULL,
        evidence TEXT,
        description TEXT,
        impact TEXT,
        remediation TEXT,
        "references" JSONB DEFAULT '[]'::jsonb,
        first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        affected_urls JSONB DEFAULT '[]'::jsonb
      );

      ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'OPEN';
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe VARCHAR(32);
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS affected_component VARCHAR(255);
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS "references" JSONB DEFAULT '[]'::jsonb;
      ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW();

      CREATE TABLE IF NOT EXISTS remediation_items (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        finding_id VARCHAR(64) NOT NULL,
        state VARCHAR(32) NOT NULL DEFAULT 'OPEN',
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'
      );

      CREATE TABLE IF NOT EXISTS attack_surface (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        inventory JSONB NOT NULL DEFAULT '{}'::jsonb,
        technologies JSONB NOT NULL DEFAULT '{}'::jsonb
      );

      CREATE TABLE IF NOT EXISTS ai_analyses (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        provider VARCHAR(64) NOT NULL,
        executive_summary TEXT,
        risk_narrative TEXT,
        remediation_roadmap JSONB DEFAULT '[]'::jsonb
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE SET NULL,
        target_url TEXT NOT NULL,
        action VARCHAR(64) NOT NULL,
        timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        details JSONB DEFAULT '{}'::jsonb
      );

      CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
      CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_remediation_scan ON remediation_items(scan_id);
      CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_logs(scan_id);
    `);
  }

  async ping(): Promise<{ ok: boolean; type: 'postgres' | 'memory'; error?: string }> {
    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query('SELECT 1');
        return { ok: true, type: 'postgres' };
      } catch (err: any) {
        return { ok: false, type: 'postgres', error: err.message };
      }
    }
    return { ok: true, type: 'memory' };
  }

  async saveScan(scan: ScanRecord): Promise<void> {
    this.memory.saveScan(scan);

    if (!this.isPostgres || !this.pool) {
      return;
    }

    const query = `
      INSERT INTO scans (id, tenant_id, target_url, target_hostname, target_scheme, target_port, authorized, status, posture, security_score, grade, risk_level, pages_scanned, duration_seconds, started_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        posture = EXCLUDED.posture,
        security_score = EXCLUDED.security_score,
        grade = EXCLUDED.grade,
        risk_level = EXCLUDED.risk_level,
        pages_scanned = EXCLUDED.pages_scanned,
        duration_seconds = EXCLUDED.duration_seconds,
        completed_at = EXCLUDED.completed_at,
        error_message = EXCLUDED.error_message
    `;
    await this.pool.query(query, [
      scan.id,
      scan.tenant_id || 'default',
      scan.target_url,
      scan.target_hostname,
      scan.target_scheme,
      scan.target_port,
      scan.authorized,
      scan.status,
      scan.posture || 'ASSESSED',
      scan.security_score,
      scan.grade,
      scan.risk_level,
      scan.pages_scanned,
      scan.duration_seconds,
      scan.started_at,
    ]);
  }

  async updateScan(id: string, updates: Partial<ScanRecord>): Promise<void> {
    this.memory.updateScan(id, updates);

    if (this.isPostgres && this.pool) {
      const keys = Object.keys(updates);
      if (keys.length === 0) return;
      const setClause = keys.map((k, i) => `${k} = $${i + 2}`).join(', ');
      const values = Object.values(updates);
      await this.pool.query(`UPDATE scans SET ${setClause} WHERE id = $1`, [id, ...values]);
    }
  }

  async getScan(id: string, tenantId?: string): Promise<ScanRecord | null> {
    if (!this.isPostgres || !this.pool) {
      return this.memory.getScan(id, tenantId);
    }

    let query = 'SELECT * FROM scans WHERE id = $1';
    const params: any[] = [id];
    if (tenantId && tenantId !== '*') {
      query += ' AND tenant_id = $2';
      params.push(tenantId);
    }

    const res = await this.pool.query(query, params);
    if (res.rows.length === 0) return null;

    const row = res.rows[0];
    const findings = await this.getFindings(id, tenantId);

    return {
      id: row.id,
      tenant_id: row.tenant_id || 'default',
      target_url: row.target_url,
      target_hostname: row.target_hostname,
      target_scheme: row.target_scheme,
      target_port: row.target_port,
      authorized: row.authorized,
      status: row.status,
      posture: row.posture || 'ASSESSED',
      security_score: row.security_score,
      grade: row.grade,
      risk_level: row.risk_level,
      pages_scanned: row.pages_scanned,
      duration_seconds: parseFloat(row.duration_seconds || '0'),
      started_at: row.started_at,
      completed_at: row.completed_at,
      error_message: row.error_message,
      findings,
    };
  }

  async listScans(tenantId?: string, limit: number = 50, offset: number = 0): Promise<{ scans: ScanRecord[]; total: number }> {
    if (!this.isPostgres || !this.pool) {
      return this.memory.listScans(tenantId, limit, offset);
    }

    let query = 'SELECT * FROM scans';
    let countQuery = 'SELECT COUNT(*) FROM scans';
    const params: any[] = [];

    if (tenantId && tenantId !== '*') {
      query += ' WHERE tenant_id = $1';
      countQuery += ' WHERE tenant_id = $1';
      params.push(tenantId);
    }

    query += ` ORDER BY started_at DESC LIMIT ${limit} OFFSET ${offset}`;

    const [res, countRes] = await Promise.all([
      this.pool.query(query, params),
      this.pool.query(countQuery, params),
    ]);

    const total = parseInt(countRes.rows[0].count, 10) || 0;
    const scans = res.rows.map(row => ({
      id: row.id,
      tenant_id: row.tenant_id || 'default',
      target_url: row.target_url,
      target_hostname: row.target_hostname,
      target_scheme: row.target_scheme,
      target_port: row.target_port,
      authorized: row.authorized,
      status: row.status,
      posture: row.posture || 'ASSESSED',
      security_score: row.security_score,
      grade: row.grade,
      risk_level: row.risk_level,
      pages_scanned: row.pages_scanned,
      duration_seconds: parseFloat(row.duration_seconds || '0'),
      started_at: row.started_at,
      completed_at: row.completed_at,
      error_message: row.error_message,
      findings: [],
    }));

    return { scans, total };
  }

  async deleteScan(id: string, tenantId: string = 'default'): Promise<boolean> {
    const memResult = this.memory.deleteScan(id, tenantId);

    if (this.isPostgres && this.pool) {
      let query = 'DELETE FROM scans WHERE id = $1';
      const params: any[] = [id];
      if (tenantId !== '*') {
        query += ' AND tenant_id = $2';
        params.push(tenantId);
      }
      const res = await this.pool.query(query, params);
      return (res.rowCount || 0) > 0;
    }

    return memResult;
  }

  async saveFindings(scanId: string, findings: Finding[], tenantId: string = 'default'): Promise<void> {
    const sanitized = findings.map(f => ({
      ...f,
      tenant_id: tenantId,
      status: f.status || 'OPEN',
      evidence: sanitizeLogString(f.evidence || ''),
    }));

    this.memory.saveFindings(scanId, sanitized, tenantId);

    if (this.isPostgres && this.pool) {
      for (const f of sanitized) {
        await this.pool.query(
          `INSERT INTO findings (id, scan_id, tenant_id, scanner, title, severity, confidence, status, category, owasp, cwe, affected_component, url, evidence, description, impact, remediation, "references", first_seen, affected_urls)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
           ON CONFLICT (id) DO UPDATE SET
             status = EXCLUDED.status,
             evidence = EXCLUDED.evidence,
             affected_urls = EXCLUDED.affected_urls`,
          [
            f.id,
            scanId,
            tenantId,
            f.scanner,
            f.title,
            f.severity,
            f.confidence,
            f.status || 'OPEN',
            f.category,
            f.owasp,
            f.cwe || 'CWE-693',
            f.affected_component || f.scanner,
            f.url,
            f.evidence,
            f.description,
            f.impact,
            f.remediation,
            JSON.stringify(f.references || []),
            f.first_seen || new Date().toISOString(),
            JSON.stringify(f.affected_urls || [f.url]),
          ]
        );
      }
    }
  }

  async getFindings(scanId: string, tenantId?: string): Promise<Finding[]> {
    if (!this.isPostgres || !this.pool) {
      return this.memory.getFindings(scanId, tenantId);
    }

    let query = 'SELECT * FROM findings WHERE scan_id = $1';
    const params: any[] = [scanId];
    if (tenantId && tenantId !== '*') {
      query += ' AND tenant_id = $2';
      params.push(tenantId);
    }

    const res = await this.pool.query(query, params);
    return res.rows.map(r => ({
      id: r.id,
      tenant_id: r.tenant_id,
      scanner: r.scanner,
      title: r.title,
      severity: r.severity,
      confidence: r.confidence,
      status: r.status || 'OPEN',
      category: r.category,
      owasp: r.owasp,
      cwe: r.cwe || 'CWE-693',
      affected_component: r.affected_component || r.scanner,
      url: r.url,
      evidence: r.evidence,
      description: r.description,
      impact: r.impact,
      remediation: r.remediation,
      references: typeof r.references === 'string' ? JSON.parse(r.references) : (r.references || []),
      first_seen: r.first_seen,
      firstSeen: r.first_seen,
      scan_id: scanId,
      scanId: scanId,
      affected_urls: typeof r.affected_urls === 'string' ? JSON.parse(r.affected_urls) : (r.affected_urls || [r.url]),
    }));
  }

  async updateFindingStatus(scanId: string, findingId: string, status: FindingStatus, tenantId: string = 'default'): Promise<boolean> {
    const memResult = this.memory.updateFindingStatus(scanId, findingId, status, tenantId);

    if (this.isPostgres && this.pool) {
      let query = 'UPDATE findings SET status = $1 WHERE id = $2 AND scan_id = $3';
      const params: any[] = [status, findingId, scanId];
      if (tenantId !== '*') {
        query += ' AND tenant_id = $4';
        params.push(tenantId);
      }
      const res = await this.pool.query(query, params);
      return (res.rowCount || 0) > 0;
    }

    return memResult;
  }

  async getTargetHistory(tenantId?: string): Promise<TargetHistoryGroup[]> {
    if (!this.isPostgres || !this.pool) {
      return this.memory.getTargetHistory(tenantId);
    }

    const { scans } = await this.listScans(tenantId, 500, 0);
    const groups = new Map<string, ScanRecord[]>();

    for (const scan of scans) {
      const origin = normalizeTargetOrigin(scan.target_url);
      if (!groups.has(origin)) {
        groups.set(origin, []);
      }
      groups.get(origin)!.push(scan);
    }

    const result: TargetHistoryGroup[] = [];
    for (const [origin, scanList] of groups.entries()) {
      const sorted = scanList.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
      const latest = sorted[0];

      result.push({
        normalized_target: origin,
        target_hostname: latest.target_hostname,
        target_port: latest.target_port,
        target_scheme: latest.target_scheme,
        scan_count: sorted.length,
        latest_score: latest.security_score,
        latest_grade: latest.grade,
        latest_risk: latest.risk_level,
        latest_posture: latest.posture || 'ASSESSED',
        latest_scan_id: latest.id,
        scans: sorted.map(s => ({
          id: s.id,
          started_at: s.started_at,
          security_score: s.security_score,
          grade: s.grade,
          risk_level: s.risk_level,
          posture: s.posture || 'ASSESSED',
          findings_count: (s.findings || []).length,
          duration_seconds: s.duration_seconds,
          status: s.status,
        })),
      });
    }

    return result.sort((a, b) => (b.latest_score ?? 0) - (a.latest_score ?? 0));
  }

  async getRemediationItems(scanId: string, tenantId?: string): Promise<RemediationItem[]> {
    return this.memory.getRemediationItems(scanId, tenantId);
  }

  async saveRemediationItem(scanId: string, findingId: string, state: RemediationState, tenantId: string = 'default'): Promise<RemediationItem | null> {
    return this.memory.saveRemediationItem(scanId, findingId, state, tenantId);
  }

  async saveAttackSurface(scanId: string, inventory: AttackSurface, technologies: TechnologySummary): Promise<void> {
    this.memory.saveAttackSurface(scanId, inventory, technologies);
    if (this.isPostgres && this.pool) {
      await this.pool.query(
        `INSERT INTO attack_surface (id, scan_id, inventory, technologies)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING`,
        [uuidv4(), scanId, JSON.stringify(inventory), JSON.stringify(technologies)]
      );
    }
  }

  async saveAIAnalysis(scanId: string, analysis: AIAnalysis): Promise<void> {
    this.memory.saveAIAnalysis(scanId, analysis);
    if (this.isPostgres && this.pool) {
      await this.pool.query(
        `INSERT INTO ai_analyses (id, scan_id, provider, executive_summary, risk_narrative, remediation_roadmap)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING`,
        [uuidv4(), scanId, analysis.provider, analysis.executive_summary, analysis.risk_narrative, JSON.stringify(analysis.remediation_roadmap)]
      );
    }
  }

  async logAudit(scanId: string | null, targetUrl: string, action: string, details: any = {}): Promise<void> {
    this.memory.logAudit(scanId, targetUrl, action, details);
    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO audit_logs (id, scan_id, target_url, action, timestamp, details)
           VALUES ($1, $2, $3, $4, NOW(), $5)`,
          [uuidv4(), scanId, targetUrl, action, JSON.stringify(details)]
        );
      } catch (e) {
        // Safe catch for audit logs
      }
    }
  }
}

export const db = new DatabaseAdapter();
