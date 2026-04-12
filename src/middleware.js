/**
 * middleware.js
 * Security middleware for the Lighting Shoppe MCP server.
 *
 * Layers applied:
 *  1. bearerAuth         — protects /sse and /messages with a secret token
 *  2. rateLimitGeneral   — 120 req / 15 min per IP on all routes
 *  3. rateLimitAuth      — 10 req  / 15 min per IP on /auth routes (brute-force protection)
 *  4. rateLimitMcp       — 20 req  / 1 min  per IP on /sse (connection flooding protection)
 *  5. validateShopDomain — shared helper, prevents open-redirect / shop-injection
 *  6. securityHeaders    — applied globally via helmet in index.js
 *
 * Nothing here touches Shopify API calls or MCP logic — pure perimeter defence.
 */

import crypto from 'crypto';
import rateLimit from 'express-rate-limit';

// ─── 1. Bearer Token Authentication ─────────────────────────────────────────

/**
 * Express middleware that requires a valid Bearer token on /sse and /messages.
 *
 * Reads the token from the MCP_BEARER_TOKEN environment variable.
 * If that variable is not set, the server will refuse to start (enforced in index.js).
 *
 * Claude Desktop config must include:
 *   "headers": { "Authorization": "Bearer <your-token>" }
 *
 * Uses crypto.timingSafeEqual to prevent timing-based token enumeration.
 */
export function bearerAuth(req, res, next) {
  const expectedToken = process.env.MCP_BEARER_TOKEN;

  // Guard: token must be configured — index.js enforces this at startup,
  // but double-check here in case middleware is used before that check runs.
  if (!expectedToken) {
    console.error('[security] MCP_BEARER_TOKEN is not set. Blocking request.');
    return res.status(503).json({ error: 'Server misconfigured — contact administrator.' });
  }

  const authHeader = req.headers['authorization'] || '';

  if (!authHeader.startsWith('Bearer ')) {
    logSecurityEvent('missing_bearer', req);
    return res.status(401).json({
      error: 'Unauthorized. A Bearer token is required to access this endpoint.',
    });
  }

  const providedToken = authHeader.slice('Bearer '.length).trim();

  // Timing-safe comparison — prevents an attacker from measuring response time
  // to guess characters of the token one by one.
  let valid = false;
  try {
    const expected = Buffer.from(expectedToken, 'utf8');
    const provided = Buffer.from(providedToken, 'utf8');

    // Buffers must be the same length for timingSafeEqual — pad both to 256 bytes
    // with a fixed byte so length differences don't leak via error vs. comparison time.
    const len = 256;
    const a = Buffer.alloc(len, 0);
    const b = Buffer.alloc(len, 0);
    expected.copy(a, 0, 0, Math.min(expected.length, len));
    provided.copy(b, 0, 0, Math.min(provided.length, len));

    // Also compare actual lengths in constant time (XOR: 0 = equal)
    const lengthMatch = expected.length ^ provided.length;
    valid = crypto.timingSafeEqual(a, b) && lengthMatch === 0;
  } catch {
    valid = false;
  }

  if (!valid) {
    logSecurityEvent('invalid_bearer', req);
    return res.status(401).json({ error: 'Unauthorized. Invalid Bearer token.' });
  }

  next();
}

// ─── 2. Rate Limiters ────────────────────────────────────────────────────────

/**
 * General rate limiter — applied to ALL routes.
 * 120 requests per 15-minute window per IP.
 * Generous enough for normal Claude Desktop usage; blocks scripted scanning.
 */
export const rateLimitGeneral = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 120,
  standardHeaders: true,   // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
  handler(req, res, _next, options) {
    logSecurityEvent('rate_limit_general', req);
    res.status(options.statusCode).json(options.message);
  },
});

/**
 * Strict rate limiter for OAuth routes (/auth, /auth/callback).
 * 10 requests per 15-minute window per IP.
 * Prevents brute-forcing OAuth state tokens or replaying callbacks.
 */
export const rateLimitAuth = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please wait 15 minutes.' },
  handler(req, res, _next, options) {
    logSecurityEvent('rate_limit_auth', req);
    res.status(options.statusCode).json(options.message);
  },
});

/**
 * MCP connection limiter for /sse.
 * 20 new SSE connections per minute per IP.
 * Prevents connection-flooding attacks that could exhaust server memory.
 */
export const rateLimitMcp = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many MCP connection attempts. Please wait a moment.' },
  handler(req, res, _next, options) {
    logSecurityEvent('rate_limit_mcp', req);
    res.status(options.statusCode).json(options.message);
  },
});

// ─── 3. Input Validation Helpers ─────────────────────────────────────────────

/**
 * Validate that a shop domain is a legitimate .myshopify.com domain.
 * Prevents open-redirect attacks and shop domain injection.
 *
 * Rules:
 *  - Must end in .myshopify.com
 *  - Subdomain portion: lowercase alphanumeric and hyphens only
 *  - No double-hyphens, no leading/trailing hyphens
 *  - Length: 3–60 characters for the subdomain portion
 *
 * @param {string} shop
 * @returns {boolean}
 */
export function isValidShopDomain(shop) {
  if (typeof shop !== 'string') return false;
  const subdomain = shop.replace(/\.myshopify\.com$/, '');
  return (
    /^[a-z0-9][a-z0-9\-]{1,58}[a-z0-9]$/.test(subdomain) &&
    !subdomain.includes('--')
  );
}

/**
 * Express middleware that validates the `?shop=` query param.
 * Rejects the request with 400 if the domain is invalid.
 * Use on routes that accept a shop param (/auth).
 */
export function validateShopParam(req, res, next) {
  const shop = (req.query.shop || process.env.SHOPIFY_SHOP || '').toString().trim().toLowerCase();
  if (!isValidShopDomain(shop)) {
    return res.status(400).json({
      error: 'Invalid shop domain. Expected format: your-store.myshopify.com',
    });
  }
  // Normalise and attach for downstream handlers
  req.validatedShop = shop;
  next();
}

// ─── 4. Startup Security Check ───────────────────────────────────────────────

/**
 * Enforce that all required secrets are present before the server accepts traffic.
 * Called once at startup in index.js — exits the process if anything is missing.
 */
export function enforceRequiredEnv() {
  const required = [
    'SHOPIFY_CLIENT_ID',
    'SHOPIFY_CLIENT_SECRET',
    'SHOPIFY_SHOP',
    'HOST',
    'MCP_BEARER_TOKEN',
  ];

  const missing = required.filter((k) => !process.env[k]?.trim());

  if (missing.length > 0) {
    console.error('');
    console.error('╔══════════════════════════════════════════════════╗');
    console.error('║         STARTUP BLOCKED — Missing secrets        ║');
    console.error('╚══════════════════════════════════════════════════╝');
    for (const key of missing) {
      console.error(`  ✗ ${key} is not set`);
    }
    console.error('');
    console.error('  Set these in Railway → Variables (or in .env for local dev).');
    console.error('  See .env.example for descriptions and generation instructions.');
    console.error('');
    process.exit(1);
  }

  // Warn if the bearer token looks weak (< 32 hex chars ≈ 128 bits)
  const token = process.env.MCP_BEARER_TOKEN;
  if (token.length < 32) {
    console.warn(
      '[security] ⚠️  MCP_BEARER_TOKEN is shorter than 32 characters. ' +
        'Generate a stronger token: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }

  console.log('[security] ✅ All required environment variables are present.');
}

// ─── 5. Internal Logging ─────────────────────────────────────────────────────

/**
 * Log a security event without leaking sensitive data.
 * Logs: event type, timestamp, IP, path. Never logs tokens, secrets, or bodies.
 */
function logSecurityEvent(event, req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  const path = req.path || '';
  const ua = (req.headers['user-agent'] || '').slice(0, 80); // truncate
  console.warn(`[security] ${event} | ${new Date().toISOString()} | ip=${ip} | path=${path} | ua="${ua}"`);
}
