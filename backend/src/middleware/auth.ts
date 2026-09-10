import { Request, Response, NextFunction } from 'express';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      tenantId: string;
      userRole?: string;
    }
  }
}

// In-memory or configured token-to-tenant registry
const KNOWN_TENANT_TOKENS: Record<string, { tenantId: string; role: string }> = {
  'alpha-secret-token': { tenantId: 'tenant-alpha', role: 'member' },
  'beta-secret-token': { tenantId: 'tenant-beta', role: 'member' },
  'gamma-secret-token': { tenantId: 'tenant-gamma', role: 'member' },
  'system-admin-token': { tenantId: '*', role: 'admin' },
};

const TENANT_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * Tenant Authorization Middleware
 * Strictly derives and validates the effective tenant ID.
 * Prevents user-controlled X-Tenant-ID from accessing arbitrary tenants.
 */
export function tenantMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'] || '';
  const requestedTenant = req.headers['x-tenant-id'] as string | undefined;

  let authenticatedTenant: string | null = null;
  let userRole = 'anonymous';

  // 1. Extract and verify bearer token if present
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const profile = KNOWN_TENANT_TOKENS[token];

    if (!profile) {
      res.status(401).json({
        success: false,
        error: 'Authentication failed: Invalid or expired Bearer token.',
      });
      return;
    }

    authenticatedTenant = profile.tenantId;
    userRole = profile.role;
  }

  // 2. Validate format of requestedTenant header if provided
  if (requestedTenant) {
    if (!TENANT_ID_REGEX.test(requestedTenant)) {
      res.status(400).json({
        success: false,
        error: 'Invalid tenant identifier format. Must be alphanumeric, dashes or underscores (1-64 chars).',
      });
      return;
    }
  }

  // 3. Reconcile authenticated identity vs requested tenant
  let effectiveTenant = 'default';

  if (authenticatedTenant) {
    if (authenticatedTenant === '*') {
      // Admin token can explicitly select tenant via X-Tenant-ID or default to admin
      effectiveTenant = requestedTenant || 'default';
    } else {
      // Non-admin token: If X-Tenant-ID is supplied, it MUST match authenticated tenant
      if (requestedTenant && requestedTenant !== authenticatedTenant) {
        res.status(403).json({
          success: false,
          error: `Tenant authorization denied: Token for '${authenticatedTenant}' cannot access tenant '${requestedTenant}'.`,
        });
        return;
      }
      effectiveTenant = authenticatedTenant;
    }
  } else {
    // Unauthenticated request
    if (requestedTenant && requestedTenant !== 'default') {
      res.status(401).json({
        success: false,
        error: `Authentication required: Cannot access isolated tenant '${requestedTenant}' without valid credentials.`,
      });
      return;
    }
    effectiveTenant = 'default';
  }

  req.tenantId = effectiveTenant;
  req.userRole = userRole;
  next();
}
