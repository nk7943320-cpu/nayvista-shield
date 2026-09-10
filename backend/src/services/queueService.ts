import { Queue, Worker } from 'bullmq';
import { config } from '../config.js';
import { db } from '../db/index.js';
import { scannerService } from './scannerService.js';
import { logger } from '../utils/logger.js';

interface ScanJobData {
  scanId: string;
}

class QueueService {
  private queue: Queue | null = null;
  private worker: Worker | null = null;
  public isRedis = false;

  // In-process FIFO queue and concurrency tracking
  private inProcessQueue: string[] = [];
  private activeInProcessCount = 0;

  async init(): Promise<void> {
    if (config.redisUrl) {
      try {
        const queueName = 'sentinelscan-jobs';
        this.queue = new Queue(queueName, {
          connection: { url: config.redisUrl, connectTimeout: 3000 },
        });

        // If not standalone API mode, initialize worker as well
        if (config.serviceType !== 'api') {
          this.worker = new Worker(
            queueName,
            async (job) => {
              logger.info(`[Worker] Processing scan job ${job.id}`, { scanId: job.data.scanId, event: 'scan_started' });
              await scannerService.executeScan(job.data.scanId);
            },
            {
              connection: { url: config.redisUrl },
              concurrency: config.maxConcurrentScans,
            }
          );

          this.worker.on('failed', (job, err) => {
            logger.error(`[Worker] Job failed in Redis queue`, err, { scanId: job?.data?.scanId, event: 'worker_failure' });
          });
        }

        this.isRedis = true;
        logger.info('[Queue] Redis + BullMQ initialized successfully.', {
          serviceType: config.serviceType,
          concurrency: config.maxConcurrentScans,
        });
      } catch (err: any) {
        logger.warn(`[Queue] Redis connection failed (${err.message}). Using resilient in-process queue with concurrency control.`);
        this.queue = null;
        this.worker = null;
        this.isRedis = false;
      }
    } else {
      logger.info('[Queue] No REDIS_URL configured. Using resilient in-process queue with concurrency control.', {
        concurrency: config.maxConcurrentScans,
      });
    }
  }

  async initWorkerOnly(): Promise<void> {
    if (!config.redisUrl) {
      throw new Error('REDIS_URL is required to run a dedicated worker process.');
    }

    const queueName = 'sentinelscan-jobs';
    this.worker = new Worker(
      queueName,
      async (job) => {
        logger.info(`[Dedicated Worker] Processing scan job ${job.id}`, { scanId: job.data.scanId, event: 'scan_started' });
        await scannerService.executeScan(job.data.scanId);
      },
      {
        connection: { url: config.redisUrl },
        concurrency: config.maxConcurrentScans,
      }
    );

    this.worker.on('failed', (job, err) => {
      logger.error(`[Dedicated Worker] Job failed`, err, { scanId: job?.data?.scanId, event: 'worker_failure' });
    });

    logger.info(`[Dedicated Worker] Worker started, listening for jobs on queue '${queueName}' with concurrency ${config.maxConcurrentScans}.`);
  }

  async addScanJob(scanId: string): Promise<void> {
    // Explicit transition to queued state
    await db.updateScan(scanId, { status: 'queued' });
    logger.info(`[Queue] Scan enqueued`, { scanId, status: 'queued', event: 'scan_queued' });

    if (this.isRedis && this.queue) {
      await this.queue.add('scan-job', { scanId }, {
        removeOnComplete: true,
        removeOnFail: false,
      });
    } else {
      // In-process queue with strict concurrency limit
      this.inProcessQueue.push(scanId);
      this.dispatchInProcess();
    }
  }

  private dispatchInProcess(): void {
    while (this.activeInProcessCount < config.maxConcurrentScans && this.inProcessQueue.length > 0) {
      const nextScanId = this.inProcessQueue.shift();
      if (!nextScanId) break;

      this.activeInProcessCount++;
      setImmediate(async () => {
        try {
          await scannerService.executeScan(nextScanId);
        } catch (err: any) {
          logger.error(`[InProcessQueue] Error executing scan ${nextScanId}`, err, { scanId: nextScanId, event: 'scan_failed' });
        } finally {
          this.activeInProcessCount--;
          this.dispatchInProcess();
        }
      });
    }
  }

  async ping(): Promise<{ ok: boolean; type: 'redis' | 'in-process'; error?: string; waiting?: number; active?: number }> {
    if (this.isRedis && this.queue) {
      try {
        const counts = await this.queue.getJobCounts('waiting', 'active', 'completed', 'failed');
        return {
          ok: true,
          type: 'redis',
          waiting: counts.waiting,
          active: counts.active,
        };
      } catch (err: any) {
        return { ok: false, type: 'redis', error: err.message };
      }
    }
    return {
      ok: true,
      type: 'in-process',
      waiting: this.inProcessQueue.length,
      active: this.activeInProcessCount,
    };
  }
}

export const queueService = new QueueService();
