import { Router, Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { validateTargetUrl, ValidationError } from '../services/urlValidator.js';
import { db } from '../db/index.js';
import { queueService } from '../services/queueService.js';
import { scannerService } from '../services/scannerService.js';
import { reportService } from '../services/reportService.js';
import { comparisonService } from '../services/comparisonService.js';
import { ScanRecord, FindingStatus, RemediationState } from '../types/index.js';
import { logger } from '../utils/logger.js';

const router = Router();
const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

function isValidId(id: string): boolean {
  return typeof id === 'string' && SAFE_ID_REGEX.test(id);
}

// Default response header guarantee for all scan routes
router.use((_req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  next();
});

// GET /api/scans/targets/history - Group historical scans by normalized target origin
router.get('/targets/history', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId || 'default';
    const targets = await db.getTargetHistory(tenantId);
    res.json({ success: true, targets });
  } catch (err: any) {
    logger.error('[API] Error retrieving target history:', err);
    res.status(500).json({ success: false, error: 'Failed to retrieve target history.' });
  }
});

// POST /api/scans - Create and start a security scan
router.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const { target, authorized, mode } = req.body || {};
    const tenantId = req.tenantId || 'default';

    // Attack simulation mode guard: strictly disabled in this phase
    if (mode && typeof mode === 'string' && (mode.toLowerCase().includes('attack') || mode.toLowerCase().includes('simulat'))) {
      res.status(400).json({
        ok: false,
        success: false,
        error: 'ATTACK SIMULATION mode is disabled. Coming in a future authorized-testing phase.',
      });
      return;
    }

    // Explicit server-side authorization check
    if (authorized !== true) {
      res.status(400).json({
        ok: false,
        success: false,
        error: 'Security testing must be explicitly authorized. Please confirm authorization before initiating a scan.',
      });
      return;
    }

    if (!target || typeof target !== 'string' || !target.trim()) {
      res.status(400).json({
        ok: false,
        success: false,
        error: 'A target URL must be specified.',
      });
      return;
    }

    // Server-side validation and SSRF protection
    const validated = await validateTargetUrl(target, true);

    const isModeActive = mode && typeof mode === 'string' && (mode.toLowerCase().includes('active') || mode.toLowerCase().includes('authoriz'));
    const scanMode = isModeActive ? 'ACTIVE / AUTHORIZED TESTING' : 'DEFENSIVE / SAFE';

    const scanId = uuidv4();
    const newScan: ScanRecord = {
      id: scanId,
      tenant_id: tenantId,
      target_url: validated.url,
      target_hostname: validated.hostname,
      target_scheme: validated.scheme,
      target_port: validated.port,
      authorized: true,
      mode: scanMode,
      status: 'pending',
      posture: 'ASSESSED',
      security_score: 100,
      grade: 'A',
      risk_level: 'LOW',
      pages_scanned: 0,
      duration_seconds: 0,
      started_at: new Date().toISOString(),
      findings: [],
    };

    await db.saveScan(newScan);
    await db.logAudit(scanId, validated.url, 'SCAN_REQUESTED', { client_ip: req.ip, tenant_id: tenantId });
    logger.info(`[API] New scan requested`, { scanId, tenantId, target: validated.hostname, event: 'scan_created' });

    // Enqueue scan execution (transitions status to 'queued')
    await queueService.addScanJob(scanId);

    const responsePayload = {
      scanId: newScan.id,
      tenant_id: newScan.tenant_id,
      status: 'queued' as const,
      mode: newScan.mode,
      target: newScan.target_url,
      hostname: newScan.target_hostname,
    };

    res.status(201).json({
      ok: true,
      success: true,
      ...responsePayload,
      data: responsePayload,
    });
  } catch (err: any) {
    if (err instanceof ValidationError) {
      res.status(400).json({
        ok: false,
        success: false,
        error: err.message,
        error_details: {
          category: err.category,
          code: err.code,
          message: err.message,
          retryable: err.retryable,
        },
      });
      return;
    }
    logger.error('[API] Error creating scan:', err);
    res.status(500).json({
      ok: false,
      success: false,
      error: 'Internal server error processing scan request.',
      error_details: {
        category: 'PLATFORM_FAILURE',
        code: 'PLATFORM_ERROR',
        message: 'Internal server error processing scan request.',
        retryable: true,
      },
    });
  }
});

// GET /api/scans - List scan history with tenant isolation & pagination
router.get('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId || 'default';
    const limit = Math.min(Math.max(parseInt(req.query.limit as string, 10) || 50, 1), 100);
    const page = Math.max(parseInt(req.query.page as string, 10) || 1, 1);
    const offset = (page - 1) * limit;

    const { scans, total } = await db.listScans(tenantId, limit, offset);
    res.json({
      success: true,
      scans,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    });
  } catch (err: any) {
    logger.error('[API] Error listing scans:', err);
    res.status(500).json({ success: false, error: 'Failed to retrieve scan history.' });
  }
});

// GET /api/scans/:id - Get scan status and details
router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID parameter format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const scan = await db.getScan(id, tenantId);
    if (!scan) {
      res.status(404).json({ success: false, error: 'Scan not found' });
      return;
    }
    res.json({ success: true, scan });
  } catch (err: any) {
    logger.error(`[API] Error retrieving scan ${req.params.id}:`, err);
    res.status(500).json({ success: false, error: 'Failed to retrieve scan details.' });
  }
});

// DELETE /api/scans/:id - Delete historical scan record
router.delete('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID parameter format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const deleted = await db.deleteScan(id, tenantId);
    if (!deleted) {
      res.status(404).json({ success: false, error: 'Scan not found or access denied.' });
      return;
    }

    await db.logAudit(id, '', 'SCAN_DELETED', { tenantId });
    res.json({ success: true, message: 'Scan audit record deleted successfully.' });
  } catch (err: any) {
    logger.error(`[API] Error deleting scan ${req.params.id}:`, err);
    res.status(500).json({ success: false, error: 'Failed to delete scan.' });
  }
});

// GET /api/scans/:id/findings - Get findings for a scan
router.get('/:id/findings', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID parameter format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const scan = await db.getScan(id, tenantId);
    if (!scan) {
      res.status(404).json({ success: false, error: 'Scan not found' });
      return;
    }

    const { severity, category, status } = req.query;
    let findings = await db.getFindings(id, tenantId);

    if (severity) {
      findings = findings.filter(f => f.severity.toLowerCase() === String(severity).toLowerCase());
    }
    if (category) {
      findings = findings.filter(f => f.category.toLowerCase().includes(String(category).toLowerCase()));
    }
    if (status) {
      findings = findings.filter(f => (f.status || 'OPEN').toLowerCase() === String(status).toLowerCase());
    }

    res.json({ success: true, findings, total: findings.length });
  } catch (err: any) {
    logger.error(`[API] Error retrieving findings for scan ${req.params.id}:`, err);
    res.status(500).json({ success: false, error: 'Failed to retrieve findings.' });
  }
});

// PATCH /api/scans/:id/findings/:findingId - Update finding status (e.g. ACCEPTED_RISK, RESOLVED)
router.patch('/:id/findings/:findingId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id, findingId } = req.params;
    if (!isValidId(id) || !isValidId(findingId)) {
      res.status(400).json({ success: false, error: 'Invalid identifier format.' });
      return;
    }

    const { status } = req.body;
    const allowedStatuses: FindingStatus[] = ['OPEN', 'RESOLVED', 'RECURRED', 'ACCEPTED_RISK'];
    if (!allowedStatuses.includes(status)) {
      res.status(400).json({ success: false, error: `Invalid status. Must be one of: ${allowedStatuses.join(', ')}` });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const updated = await db.updateFindingStatus(id, findingId, status, tenantId);
    if (!updated) {
      res.status(404).json({ success: false, error: 'Finding or scan not found.' });
      return;
    }

    res.json({ success: true, scanId: id, findingId, status });
  } catch (err: any) {
    logger.error(`[API] Error updating finding status:`, err);
    res.status(500).json({ success: false, error: 'Failed to update finding status.' });
  }
});

// GET /api/scans/:id/remediation - Get remediation checklist
router.get('/:id/remediation', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const scan = await db.getScan(id, tenantId);
    if (!scan) {
      res.status(404).json({ success: false, error: 'Scan not found' });
      return;
    }

    const items = await db.getRemediationItems(id, tenantId);
    res.json({ success: true, items });
  } catch (err: any) {
    logger.error(`[API] Error retrieving remediation items:`, err);
    res.status(500).json({ success: false, error: 'Failed to retrieve remediation checklist.' });
  }
});

// PUT /api/scans/:id/remediation/:findingId - Update remediation checklist item
router.put('/:id/remediation/:findingId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id, findingId } = req.params;
    if (!isValidId(id) || !isValidId(findingId)) {
      res.status(400).json({ success: false, error: 'Invalid identifier format.' });
      return;
    }

    const { state } = req.body;
    const allowedStates: RemediationState[] = ['OPEN', 'IN_PROGRESS', 'COMPLETED'];
    if (!allowedStates.includes(state)) {
      res.status(400).json({ success: false, error: `Invalid state. Must be one of: ${allowedStates.join(', ')}` });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const item = await db.saveRemediationItem(id, findingId, state, tenantId);
    if (!item) {
      res.status(404).json({ success: false, error: 'Finding or scan not found.' });
      return;
    }

    res.json({ success: true, item });
  } catch (err: any) {
    logger.error(`[API] Error updating remediation item:`, err);
    res.status(500).json({ success: false, error: 'Failed to update remediation state.' });
  }
});

// GET /api/scans/:id/compare/:targetId - Compare two scans deterministically
router.get('/:id/compare/:targetId', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id, targetId } = req.params;
    if (!isValidId(id) || !isValidId(targetId)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const baseScan = await db.getScan(id, tenantId);
    const targetScan = await db.getScan(targetId, tenantId);

    if (!baseScan || !targetScan) {
      res.status(404).json({
        success: false,
        error: 'One or both scan records not found or access denied for this tenant.',
      });
      return;
    }

    const { scans: allTargetScans } = await db.listScans(tenantId, 100, 0);
    const priorScans = allTargetScans.filter(s => s.target_hostname === baseScan.target_hostname);

    const comparison = comparisonService.compareScans(baseScan, targetScan, priorScans);
    res.json({ success: true, comparison });
  } catch (err: any) {
    logger.error(`[API] Error comparing scans:`, err);
    res.status(500).json({ success: false, error: 'Failed to compare scans.' });
  }
});

// GET /api/scans/:id/report - Download or view report
router.get('/:id/report', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const scan = await db.getScan(id, tenantId);
    if (!scan) {
      res.status(404).json({ success: false, error: 'Scan not found' });
      return;
    }

    const findings = await db.getFindings(id, tenantId);
    const format = (req.query.format as string) || 'json';

    if (format.toLowerCase() === 'html') {
      const html = reportService.generateHtmlReport(scan, findings);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } else {
      const jsonReport = reportService.generateJsonReport(scan, findings);
      res.json(jsonReport);
    }
  } catch (err: any) {
    logger.error(`[API] Error generating report for scan ${req.params.id}:`, err);
    res.status(500).json({ success: false, error: 'Failed to generate report.' });
  }
});

// POST /api/scans/:id/cancel - Cancel active scan
router.post('/:id/cancel', async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) {
      res.status(400).json({ success: false, error: 'Invalid scan ID format.' });
      return;
    }

    const tenantId = req.tenantId || 'default';
    const scan = await db.getScan(id, tenantId);
    if (!scan) {
      res.status(404).json({ success: false, error: 'Scan not found' });
      return;
    }

    const cancelled = scannerService.cancelScan(id);
    if (cancelled) {
      await db.logAudit(id, '', 'SCAN_CANCELLED', { tenantId });
      res.json({ success: true, message: 'Scan cancelled' });
    } else {
      res.status(400).json({ success: false, message: 'Scan is not actively running' });
    }
  } catch (err: any) {
    logger.error(`[API] Error cancelling scan ${req.params.id}:`, err);
    res.status(500).json({ success: false, error: 'Failed to cancel scan.' });
  }
});

export default router;
