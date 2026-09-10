import { createServer } from './server.js';
import { config, validateConfig } from './config.js';
import { db } from './db/index.js';
import { queueService } from './services/queueService.js';
import { logger } from './utils/logger.js';

async function bootstrap() {
  logger.info('[NayVista Shield] Initializing backend services...', {
    nodeEnv: config.nodeEnv,
    serviceType: config.serviceType,
  });

  // 1. Validate startup configuration
  validateConfig();

  // 2. Initialize Database (runs migrations if PostgreSQL)
  await db.init();

  // 3. Initialize Queue service (Redis/BullMQ or in-process fallback)
  await queueService.init();

  // 4. Start HTTP Server
  const app = createServer();

  app.listen(config.port, config.host, () => {
    logger.info(`[NayVista Shield] Server running on http://${config.host}:${config.port}`);
    logger.info(`[NayVista Shield] Local targets allowed: ${config.allowLocalTargets}`);
  });
}

bootstrap().catch((err) => {
  logger.error('[NayVista Shield] Fatal error during startup:', err);
  process.exit(1);
});
