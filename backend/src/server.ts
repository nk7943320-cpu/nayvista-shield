import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { db } from './db/index.js';
import { queueService } from './services/queueService.js';
import { logger } from './utils/logger.js';
import { tenantMiddleware } from './middleware/auth.js';
import scanRoutes from './routes/scans.js';

export function createServer(): Express {
  const app = express();

  // 1. Security Headers
  app.use(helmet({
    contentSecurityPolicy: false, // Let reverse-proxy / client define CSP if needed
    crossOriginEmbedderPolicy: false,
  }));

  // 2. CORS
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  }));

  // 3. Body Limits (Strict 1MB max payload to prevent DoS)
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  // Handle malformed JSON request bodies from body-parser
  app.use((err: any, _req: Request, res: Response, next: NextFunction): void => {
    if (err instanceof SyntaxError && ('status' in err && (err as any).status === 400 || 'body' in err)) {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.status(400).json({
        success: false,
        error: 'Malformed JSON request body.',
        code: 'INVALID_JSON',
      });
      return;
    }
    next(err);
  });

  // 4. Rate Limiting
  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // 200 requests per 15 minutes per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Too many requests. Please slow down.' },
  });

  const scanCreateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500, // Generous limit for unlimited scans while protecting API socket from flood
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Rate limit exceeded: Too many security scans initiated. Please try again later.' },
  });

  app.use('/api/', generalLimiter);
  app.use('/api/scans', scanCreateLimiter);
  app.use('/api', tenantMiddleware);

  // 5. Health Check Endpoint (/health and /api/health)
  const healthHandler = async (_req: Request, res: Response): Promise<void> => {
    const dbPing = await db.ping();
    const queuePing = await queueService.ping();

    const isHealthy = dbPing.ok && queuePing.ok;
    const statusCode = isHealthy ? 200 : 503;

    res.status(statusCode).json({
      status: isHealthy ? 'ok' : 'degraded',
      service: 'NayVista Shield API',
      timestamp: new Date().toISOString(),
      components: {
        api: { status: 'ok' },
        database: {
          status: dbPing.ok ? 'ok' : 'unhealthy',
          type: dbPing.type,
          error: dbPing.error,
        },
        queue: {
          status: queuePing.ok ? 'ok' : 'unhealthy',
          type: queuePing.type,
          waiting: queuePing.waiting,
          active: queuePing.active,
          error: queuePing.error,
        },
      },
    });
  };

  app.get('/health', healthHandler);
  app.get('/api/health', healthHandler);

  // 6. Scan API Endpoints
  app.use('/api/scans', scanRoutes);

  // 7. Global 404 Handler
  app.use((_req: Request, res: Response): void => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.status(404).json({
      success: false,
      error: 'Route not found.',
      code: 'NOT_FOUND',
    });
  });

  // 8. Global Error Handler (Hides internal stack traces in production responses)
  app.use((err: any, _req: Request, res: Response, _next: NextFunction): void => {
    logger.error('Unhandled API exception', err);
    if (!res.headersSent) {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.status(500).json({
        success: false,
        error: 'Internal server error.',
        code: 'INTERNAL_SERVER_ERROR',
      });
    }
  });

  return app;
}
