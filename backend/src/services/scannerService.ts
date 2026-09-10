import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import readline from 'readline';
import { EventEmitter } from 'events';
import { config } from '../config.js';
import { db } from '../db/index.js';
import { aiService } from '../ai/aiService.js';
import { ScanRecord, ProgressStep } from '../types/index.js';
import { logger } from '../utils/logger.js';

export class ScannerService extends EventEmitter {
  private activeProcesses = new Map<string, ChildProcess>();
  private timeoutTimers = new Map<string, NodeJS.Timeout>();

  async executeScan(scanId: string): Promise<void> {
    const scan = await db.getScan(scanId);
    if (!scan) {
      throw new Error(`Scan not found: ${scanId}`);
    }

    await db.updateScan(scanId, { status: 'running' });
    logger.info(`[Scanner] Launching security assessment for scan ${scanId}`, {
      scanId,
      target: scan.target_hostname,
      status: 'running',
      event: 'scan_started',
    });

    const scannerCliPath = path.resolve(config.scannerDir, 'scanner_cli.py');
    const args = [scannerCliPath, '--target', scan.target_url];
    if (config.allowLocalTargets) {
      args.push('--allow-local');
    }
    if (scan.mode && (scan.mode.includes('ACTIVE') || scan.mode.includes('AUTHORIZED'))) {
      args.push('--mode', 'active', '--authorized');
    }

    const child = spawn(config.pythonBin, args, {
      cwd: config.scannerDir,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
        PYTHONPATH: path.dirname(config.scannerDir),
      },
    });

    this.activeProcesses.set(scanId, child);

    // Watchdog timer: kill process if it exceeds configured timeout
    const timer = setTimeout(async () => {
      const activeProcess = this.activeProcesses.get(scanId);
      if (activeProcess) {
        logger.warn(`[Scanner] Scan exceeded watchdog timeout of ${config.scanTimeoutMs}ms. Aborting.`, {
          scanId,
          status: 'timeout',
          event: 'scan_timeout',
        });
        try {
          activeProcess.kill('SIGTERM');
          setTimeout(() => {
            try {
              if (this.activeProcesses.has(scanId)) {
                activeProcess.kill('SIGKILL');
              }
            } catch {}
          }, 2000);
        } catch {}
        this.activeProcesses.delete(scanId);
        this.timeoutTimers.delete(scanId);
        const timeoutMsg = `Assessment timed out after ${Math.round(config.scanTimeoutMs / 1000)} seconds. Target took too long to respond or network connection stalled.`;
        await db.updateScan(scanId, {
          status: 'timeout',
          error_message: timeoutMsg,
          error_category: 'ASSESSMENT_LIMITATION',
          error_code: 'TARGET_TIMEOUT',
          completed_at: new Date().toISOString(),
        });
        this.emit('timeout', { scanId, error: timeoutMsg, category: 'ASSESSMENT_LIMITATION', code: 'TARGET_TIMEOUT' });
      }
    }, config.scanTimeoutMs);

    this.timeoutTimers.set(scanId, timer);

    let isCapturingResult = false;
    let resultJsonBuffer = '';
    let errorMessage = '';

    const rlOut = readline.createInterface({ input: child.stdout });
    const rlErr = readline.createInterface({ input: child.stderr });

    rlOut.on('line', async (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      if (trimmed === '===SENTINELSCAN_RESULT===' || trimmed === '===NAYVISTA_RESULT===') {
        isCapturingResult = true;
        return;
      }

      if (isCapturingResult) {
        resultJsonBuffer += line + '\n';
        return;
      }

      // Check if it's a progress event
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed.type === 'progress') {
            const progress: ProgressStep = {
              phase: parsed.phase,
              message: parsed.message,
              step: parsed.step,
              total_steps: parsed.total_steps,
              timestamp: parsed.timestamp,
              stats: parsed.stats,
            };
            await db.updateScan(scanId, { progress });
            this.emit('progress', { scanId, progress });
          }
        } catch {
          // Ignore non-json lines
        }
      }
    });

    rlErr.on('line', (line) => {
      errorMessage += line + '\n';
    });

    child.on('close', async (code) => {
      // Clear watchdog timer
      const existingTimer = this.timeoutTimers.get(scanId);
      if (existingTimer) {
        clearTimeout(existingTimer);
        this.timeoutTimers.delete(scanId);
      }
      this.activeProcesses.delete(scanId);

      // If already marked cancelled or timeout, do not overwrite
      const currentRecord = await db.getScan(scanId);
      if (currentRecord && (currentRecord.status === 'cancelled' || currentRecord.status === 'timeout')) {
        return;
      }

      if (code !== 0) {
        let cleanError = errorMessage.trim();
        try {
          const lines = cleanError.split('\n');
          for (const l of lines) {
            const trimmed = l.trim();
            if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
              const parsed = JSON.parse(trimmed);
              if (parsed.error) {
                cleanError = parsed.error;
                break;
              }
            }
          }
        } catch {
          // Keep raw or clean
        }

        if (!cleanError) {
          cleanError = `Assessment halted: Target could not be reached (Exit code ${code}).`;
        }

        logger.error(`[Scanner] Scan failed with exit code ${code}`, cleanError, {
          scanId,
          status: 'failed',
          event: 'scan_failed',
        });
        await db.updateScan(scanId, {
          status: 'failed',
          error_message: cleanError,
          error_category: 'PLATFORM_FAILURE',
          error_code: 'INTERNAL_SCANNER_ERROR',
          completed_at: new Date().toISOString(),
        });
        this.emit('failed', { scanId, error: cleanError, category: 'PLATFORM_FAILURE', code: 'INTERNAL_SCANNER_ERROR' });
        return;
      }

      try {
        const scanResult = JSON.parse(resultJsonBuffer.trim());
        const findings = scanResult.findings || [];
        const rawInv = scanResult.inventory || {};
        const inventory = {
          total_pages: typeof rawInv.total_pages === 'number' ? rawInv.total_pages : (scanResult.pages_scanned || 0),
          endpoints: Array.isArray(rawInv.endpoints) ? rawInv.endpoints : [],
          parameters: Array.isArray(rawInv.parameters) ? rawInv.parameters : [],
          forms_count: typeof rawInv.forms_count === 'number' ? rawInv.forms_count : (Array.isArray(rawInv.forms) ? rawInv.forms.length : 0),
          forms: Array.isArray(rawInv.forms) ? rawInv.forms : [],
          api_endpoints: Array.isArray(rawInv.api_endpoints) ? rawInv.api_endpoints : [],
          ...rawInv,
        };
        inventory.endpoints = Array.isArray(inventory.endpoints) ? inventory.endpoints : [];
        inventory.parameters = Array.isArray(inventory.parameters) ? inventory.parameters : [];
        inventory.forms = Array.isArray(inventory.forms) ? inventory.forms : [];
        inventory.api_endpoints = Array.isArray(inventory.api_endpoints) ? inventory.api_endpoints : [];

        const rawTech = scanResult.technologies || {};
        const technologies = {
          web_servers: Array.isArray(rawTech.web_servers) ? rawTech.web_servers : [],
          backend: Array.isArray(rawTech.backend) ? rawTech.backend : [],
          cms: Array.isArray(rawTech.cms) ? rawTech.cms : [],
          frontend: Array.isArray(rawTech.frontend) ? rawTech.frontend : [],
          libraries: Array.isArray(rawTech.libraries) ? rawTech.libraries : [],
          ...rawTech,
        };
        technologies.web_servers = Array.isArray(technologies.web_servers) ? technologies.web_servers : [];
        technologies.backend = Array.isArray(technologies.backend) ? technologies.backend : [];
        technologies.cms = Array.isArray(technologies.cms) ? technologies.cms : [];
        technologies.frontend = Array.isArray(technologies.frontend) ? technologies.frontend : [];
        technologies.libraries = Array.isArray(technologies.libraries) ? technologies.libraries : [];
        const scoring = scanResult.scoring || { score: 100, grade: 'A', risk_level: 'LOW' };
        const posture = scanResult.posture || scoring.posture || 'ASSESSED';
        const assessmentStatus = scanResult.assessment_status || (posture === 'LIMITED' ? 'COMPLETED_WITH_LIMITATIONS' : 'COMPLETED');
        const coverage = scanResult.coverage || {
          total_stages: 14,
          completed_stages: 14,
          coverage_pct: 100,
          assessment_scope: 'Comprehensive'
        };
        const stageStatus = scanResult.stage_status || {};
        const limitations = scanResult.limitations || [];
        const isLimited = posture === 'LIMITED' || limitations.length > 0;
        const securityScore = (scoring.score !== undefined && scoring.score !== null) ? scoring.score : (isLimited ? null : 100);

        // Save findings and attack surface (evidence is sanitized in saveFindings)
        await db.saveFindings(scanId, findings);
        await db.saveAttackSurface(scanId, inventory, technologies);

        // Update scan record preliminary stats
        const updatedScan: ScanRecord = {
          ...scan,
          status: 'running', // Keep running while AI finalizes
          mode: scanResult.mode || scan.mode || 'DEFENSIVE / SAFE',
          resolved_ip: scanResult.resolved_ip || 'N/A',
          dns: scanResult.dns,
          network_exposure: scanResult.network_exposure || [],
          posture,
          assessment_status: assessmentStatus,
          coverage,
          stage_status: stageStatus,
          limitations,
          is_limited: isLimited,
          security_score: securityScore,
          grade: scoring.grade,
          risk_level: scoring.risk_level,
          pages_scanned: scanResult.pages_scanned || 0,
          duration_seconds: scanResult.duration_seconds || 0,
        };
        await db.updateScan(scanId, updatedScan);

        // Run AI explanation layer
        const aiAnalysis = await aiService.analyze(updatedScan, findings);
        await db.saveAIAnalysis(scanId, aiAnalysis);

        // Mark scan completed
        await db.updateScan(scanId, {
          status: 'completed',
          completed_at: new Date().toISOString(),
          mode: scanResult.mode || scan.mode || 'DEFENSIVE / SAFE',
          resolved_ip: scanResult.resolved_ip || 'N/A',
          dns: scanResult.dns,
          network_exposure: scanResult.network_exposure || [],
          posture,
          assessment_status: assessmentStatus,
          coverage,
          stage_status: stageStatus,
          limitations,
          is_limited: isLimited,
          security_score: securityScore,
          grade: scoring.grade,
          risk_level: scoring.risk_level,
          pages_scanned: scanResult.pages_scanned || 0,
          duration_seconds: scanResult.duration_seconds || 0,
        });

        logger.info(`[Scanner] Scan completed successfully`, {
          scanId,
          status: 'completed',
          score: securityScore,
          grade: scoring.grade,
          risk: scoring.risk_level,
          posture,
          isLimited,
          event: 'scan_completed',
        });
        this.emit('completed', { scanId });
      } catch (err: any) {
        logger.error(`[Scanner] Failed to parse results for scan`, err, { scanId, status: 'failed', event: 'scan_failed' });
        await db.updateScan(scanId, {
          status: 'failed',
          error_message: `Failed to process scanner output: ${err.message}`,
          error_category: 'PLATFORM_FAILURE',
          error_code: 'MALFORMED_OUTPUT',
          completed_at: new Date().toISOString(),
        });
      }
    });
  }

  cancelScan(scanId: string): boolean {
    const timer = this.timeoutTimers.get(scanId);
    if (timer) {
      clearTimeout(timer);
      this.timeoutTimers.delete(scanId);
    }
    const process = this.activeProcesses.get(scanId);
    if (process) {
      process.kill('SIGTERM');
      this.activeProcesses.delete(scanId);
      db.updateScan(scanId, { status: 'cancelled', completed_at: new Date().toISOString() });
      logger.info(`[Scanner] Scan cancelled by user`, { scanId, status: 'cancelled', event: 'scan_cancelled' });
      return true;
    }
    return false;
  }
}

export const scannerService = new ScannerService();
