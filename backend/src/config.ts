import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(process.cwd(), '../.env') });
dotenv.config();

export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
  serviceType: (process.env.SERVICE_TYPE || 'all').toLowerCase(), // 'all' | 'api' | 'worker'
  port: parseInt(process.env.PORT || '5000', 10),
  host: process.env.HOST || '0.0.0.0',
  databaseUrl: process.env.DATABASE_URL || '',
  redisUrl: process.env.REDIS_URL || '',
  pythonBin: process.env.PYTHON_BIN || (process.platform === 'win32' ? 'py' : 'python3'),
  allowLocalTargets: process.env.ALLOW_LOCAL_TARGETS === '1' || process.env.ALLOW_LOCAL_TARGETS === 'true',
  geminiApiKey: process.env.GEMINI_API_KEY || '',
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  scanTimeoutMs: parseInt(process.env.SCAN_TIMEOUT_MS || '120000', 10),
  maxConcurrentScans: parseInt(process.env.MAX_CONCURRENT_SCANS || '2', 10),
  scannerDir: process.cwd().endsWith('backend')
    ? path.resolve(process.cwd(), '../scanner')
    : path.resolve(process.cwd(), 'scanner'),
};

export function validateConfig(): void {
  if (isNaN(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error(`Invalid PORT configuration: '${process.env.PORT}'. Must be a number between 1 and 65535.`);
  }

  if (isNaN(config.scanTimeoutMs) || config.scanTimeoutMs < 1000) {
    throw new Error(`Invalid SCAN_TIMEOUT_MS configuration: '${process.env.SCAN_TIMEOUT_MS}'. Must be at least 1000ms.`);
  }

  if (isNaN(config.maxConcurrentScans) || config.maxConcurrentScans < 1) {
    throw new Error(`Invalid MAX_CONCURRENT_SCANS configuration: '${process.env.MAX_CONCURRENT_SCANS}'. Must be at least 1.`);
  }

  if (config.isProduction && config.allowLocalTargets) {
    console.warn('[Config Warning] ALLOW_LOCAL_TARGETS is set to true in production mode. This should only be used for testing pipelines.');
  }

  // Strict production validation if specified
  if (process.env.STRICT_PRODUCTION === '1' || process.env.STRICT_PRODUCTION === 'true') {
    if (!config.databaseUrl) {
      throw new Error('STRICT_PRODUCTION is enabled but DATABASE_URL is missing. PostgreSQL is required for production.');
    }
    if (!config.redisUrl) {
      throw new Error('STRICT_PRODUCTION is enabled but REDIS_URL is missing. Redis is required for production.');
    }
  }
}
