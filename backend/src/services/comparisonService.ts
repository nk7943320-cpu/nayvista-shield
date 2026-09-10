import { ScanRecord, Finding, ScanComparison, Severity } from '../types/index.js';

export class ComparisonService {
  /**
   * Compares a base scan (Scan A, earlier) with a target scan (Scan B, later).
   * Calculates finding deltas, score/grade/risk shifts, and attack surface changes.
   * Enforces the rule: findings are only resolved if the subsequent scan was successfully assessed.
   */
  compareScans(baseScan: ScanRecord, targetScan: ScanRecord, priorScansForTarget: ScanRecord[] = []): ScanComparison {
    const baseFindings = baseScan.findings || [];
    const targetFindings = targetScan.findings || [];

    const baseMap = new Map<string, Finding>();
    for (const f of baseFindings) {
      baseMap.set(f.id, f);
    }

    const targetMap = new Map<string, Finding>();
    for (const f of targetFindings) {
      targetMap.set(f.id, f);
    }

    // Prior findings set to distinguish REGRESSED from truly NEW
    const historicallySeenFindingIds = new Set<string>();
    for (const scan of priorScansForTarget) {
      if (scan.id !== baseScan.id && scan.id !== targetScan.id) {
        for (const f of (scan.findings || [])) {
          historicallySeenFindingIds.add(f.id);
        }
      }
    }

    const newFindings: Finding[] = [];
    const persistentFindings: Finding[] = [];
    const resolvedFindings: Finding[] = [];
    const regressedFindings: Finding[] = [];

    // Evaluate target scan findings
    for (const [id, finding] of targetMap.entries()) {
      if (baseMap.has(id)) {
        persistentFindings.push({ ...finding, status: 'OPEN' });
      } else {
        if (historicallySeenFindingIds.has(id)) {
          regressedFindings.push({ ...finding, status: 'RECURRED' });
        } else {
          newFindings.push({ ...finding, status: 'OPEN' });
        }
      }
    }

    // Resolution condition:
    // A finding may only become RESOLVED when the relevant target/component was successfully assessed again.
    // If the new scan is RESTRICTED, DEGRADED, TIMEOUT, FAILED, or PARTIAL:
    // do NOT mark missing findings as resolved!
    const targetPosture = (targetScan.posture || '').toUpperCase();
    const targetStatus = targetScan.status;
    const isTargetFullyAssessed =
      targetStatus === 'completed' &&
      targetPosture === 'ASSESSED' &&
      targetScan.pages_scanned > 0;

    for (const [id, baseFinding] of baseMap.entries()) {
      if (!targetMap.has(id)) {
        if (isTargetFullyAssessed) {
          resolvedFindings.push({ ...baseFinding, status: 'RESOLVED' });
        } else {
          // Keep as persistent if scan was degraded, restricted, or incomplete
          persistentFindings.push({ ...baseFinding, status: 'OPEN' });
        }
      }
    }

    // Deltas
    const scoreDelta = (targetScan.security_score || 0) - (baseScan.security_score || 0);
    const gradeChanged = (targetScan.grade || '') !== (baseScan.grade || '');
    const riskChanged = (targetScan.risk_level || '') !== (baseScan.risk_level || '');
    const postureChanged = (targetScan.posture || '') !== (baseScan.posture || '');

    const severityList: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const severityDiff: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    for (const sev of severityList) {
      const baseCount = baseFindings.filter(f => f.severity === sev).length;
      const targetCount = targetFindings.filter(f => f.severity === sev).length;
      severityDiff[sev] = targetCount - baseCount;
    }

    const baseInventory = baseScan.inventory || { total_pages: 0, endpoints: [], forms: [], parameters: [], forms_count: 0, api_endpoints: [] };
    const targetInventory = targetScan.inventory || { total_pages: 0, endpoints: [], forms: [], parameters: [], forms_count: 0, api_endpoints: [] };

    const attackSurfaceDiff = {
      pages: (targetInventory.total_pages || 0) - (baseInventory.total_pages || 0),
      endpoints: (targetInventory.endpoints?.length || 0) - (baseInventory.endpoints?.length || 0),
      forms: (targetInventory.forms?.length || 0) - (baseInventory.forms?.length || 0),
      parameters: (targetInventory.parameters?.length || 0) - (baseInventory.parameters?.length || 0),
    };

    return {
      base_scan: baseScan,
      target_scan: targetScan,
      delta: {
        score: scoreDelta,
        grade_changed: gradeChanged,
        risk_changed: riskChanged,
        posture_changed: postureChanged,
        severity_diff: severityDiff,
        attack_surface_diff: attackSurfaceDiff,
      },
      findings: {
        new: newFindings,
        resolved: resolvedFindings,
        persistent: persistentFindings,
        regressed: regressedFindings,
      },
      summary: {
        new_count: newFindings.length,
        resolved_count: resolvedFindings.length,
        persistent_count: persistentFindings.length,
        regressed_count: regressedFindings.length,
      },
    };
  }
}

export const comparisonService = new ComparisonService();
