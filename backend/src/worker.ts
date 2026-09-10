/**
 * NayVista Shield - Dedicated Scanner Worker Process
 * Consumes assessment jobs from Redis queue, runs the isolated Python scanner,
 * and records findings and attack surface inventory directly to PostgreSQL.
 */

import { db } from './db/index.js';
import { queueService } from './services/queueService.js';
import { validateConfig, config } from './config.js';
import { logger } from './utils/logger.js';

async function bootstrapWorker() {
  logger.info('[Worker Process] Bootstrapping NayVista Shield Scanner Worker...');

  validateConfig();

  // Initialize DB connection
  await db.init();

  // Start dedicated queue worker
  await queueService.initWorkerOnly();

  logger.info(`[Worker Process] Ready and listening for scan jobs. (Concurrency limit: ${config.maxConcurrentScans})`);
}

bootstrapWorker().catch((err) => {
  logger.error('[Worker Process] Fatal startup error:', err);
  process.exit(1);
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('[Worker Process] Received SIGTERM, gracefully shutting down...');
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('[Worker Process] Received SIGINT, gracefully shutting down...');
  process.exit(0);
});
