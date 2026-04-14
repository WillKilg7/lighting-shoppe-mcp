/**
 * index.js
 * Main Express server for the Lighting Shoppe MCP app.
 *
 * Security layers (applied in order):
 *   1. enforceRequiredEnv  — blocks startup if any secret is missing
 *   2. helmet              — sets hardened HTTP security headers on every response
 *   3. rateLimitGeneral    — 120 req / 15 min per IP (all routes)
 *   4. body size limit     — rejects payloads > 100 KB
 *   5. rateLimitAuth       — 10 req  / 15 min per IP (/auth, /auth/callback)
 *   6. rateLimitMcp        — 20 req  / 1 min  per IP (/sse)
 *   7. bearerAuth          — Bearer token required on /sse and /messages
 *   8. validateShopParam   — strict .myshopify.com domain check on /auth
 *   9. HMAC validation     — on /auth/callback (Shopify-signed) and /webhooks
 *  10. Hardened errors     — no stack traces leak in production
 *
 * Routes:
 *   GET  /                          → status page / redirect to /auth
 *   GET  /health                    → JSON health check (public, rate-limited)
 *   GET  /auth                      → start Shopify OAuth
 *   GET  /auth/callback             → Shopify OAuth callback
 *   POST /webhooks/app-uninstalled  → Shopify webhook (HMAC-verified)
 *   GET  /sse                       → MCP SSE endpoint  ← Bearer token required
 *   POST /messages                  → MCP message relay ← Bearer token required
 */

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';

import {
  enforceRequiredEnv,
  bearerAuth,
  rateLimitGeneral,
  rateLimitAuth,
  rateLimitMcp,
  validateShopParam,
} from './middleware.js';

import { generateAuthUrl, handleCallback, isInstalled, revokeToken, validateWebhookHmac, getAccessToken } from './auth.js';
import { ShopifyClient } from './shopify.js';

import { createMCPServer, SSEServerTransport } from './mcp.js';

// ─── Startup Security Check ──────────────────────────────────────────────────
// Exits the process immediately if any required env var is missing.
enforceRequiredEnv();

const app = express();
const PORT = process.env.PORT || 3000;
const SHOP = process.env.SHOPIFY_SHOP;
const IS_PROD = process.env.NODE_ENV === 'production';

// ─── Global Security Headers (helmet) ───────────────────────────────────────
// Sets ~15 HTTP headers that harden against XSS, clickjacking, MIME sniffing, etc.
app.use(
  helmet({
    // Allow the success page HTML to render without a CSP violation
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // inline styles on success page
        scriptSrc: ["'none'"],
        imgSrc: ["'none'"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    // HSTS: tell browsers to only use HTTPS for 1 year
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
    // Prevent this app from being iframed anywhere
    frameguard: { action: 'deny' },
    // Don't let browsers sniff the MIME type
    noSniff: true,
    // Don't send the X-Powered-By: Express header
    hidePoweredBy: true,
    // Prevent IE from executing downloads in the site's context
    ieNoOpen: true,
    // Block XSS in older browsers
    xssFilter: true,
    // Don't send Referer header when navigating away
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// ─── Global Rate Limiting ────────────────────────────────────────────────────
// Trust Railway's reverse proxy so rate limiting uses the real client IP.
app.set('trust proxy', 1);
app.use(rateLimitGeneral);

// ─── Body Parsing + Size Limits ─────────────────────────────────────────────
// Webhook route needs the raw body for HMAC validation; everything else gets JSON.
// Hard limit of 100 KB prevents large-payload attacks.
app.use((req, res, next) => {
  if (req.path === '/webhooks/app-uninstalled') {
    let rawBody = '';
    req.on('data', (chunk) => {
      rawBody += chunk;
      if (rawBody.length > 100_000) {
        res.status(413).json({ error: 'Payload too large.' });
        req.destroy();
      }
    });
    req.on('end', () => {
      req.rawBody = rawBody;
      next();
    });
  } else {
    express.json({ limit: '100kb' })(req, res, next);
  }
});

// ─── Active SSE Transport Registry ──────────────────────────────────────────
// Maps sessionId → SSEServerTransport so POST /messages can route correctly.
// Bounded to prevent unbounded memory growth from stale sessions.
const transports = {};
const MAX_SESSIONS = 50;

// ─── Routes ─────────────────────────────────────────────────────────────────

/**
 * GET /health
 * Public health check. Returns minimal info — enough for Railway uptime monitors.
 * Does NOT expose shop tokens, session counts, or internal state.
 */
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    app: 'lighting-shoppe-mcp',
    installed: isInstalled(SHOP),
    ts: new Date().toISOString(),
  });
});

/**
 * GET /
 * Root. Redirects to /auth if not yet installed; otherwise returns status JSON.
 * Intentionally returns minimal info — no secrets, no internal paths.
 */
app.get('/', (req, res) => {
  if (!isInstalled(SHOP)) {
    return res.redirect('/auth');
  }
  res.json({
    name: 'Lighting Shoppe MCP',
    status: 'connected',
    endpoints: { health: '/health', auth: '/auth', mcp: '/sse' },
  });
});

/**
 * GET /auth
 * Initiates Shopify OAuth.
 * Protected by: rateLimitAuth + validateShopParam (domain injection prevention).
 */
app.get('/auth', rateLimitAuth, validateShopParam, (req, res) => {
  const shop = req.validatedShop;
  const { url } = generateAuthUrl(shop);
  console.log(`[auth] Starting OAuth for shop: ${shop}`);
  res.redirect(url);
});

/**
 * GET /auth/callback
 * Receives the Shopify authorization code.
 * Protected by: rateLimitAuth + Shopify HMAC validation (inside handleCallback).
 */
app.get('/auth/callback', rateLimitAuth, async (req, res) => {
  const { shop, code, state, hmac } = req.query;

  // Reject if any required param is missing
  if (!shop || !code || !state || !hmac) {
    return res.status(400).json({
      error: 'Missing required OAuth parameters.',
    });
  }

  // Basic shop domain check before doing anything
  if (!/^[a-z0-9][a-z0-9\-]*\.myshopify\.com$/.test(shop.toString().toLowerCase())) {
    return res.status(400).json({ error: 'Invalid shop domain.' });
  }

  try {
    await handleCallback(
      shop.toString(),
      code.toString(),
      state.toString(),
      hmac.toString(),
      req.query
    );

    const host = process.env.HOST;
    res.send(successPage(shop.toString(), host));
  } catch (err) {
    // Log the real error internally; return a generic message externally
    console.error('[auth] OAuth callback error:', err.message);
    res.status(400).send(errorPage('Authentication failed. Please try again.'));
  }
});

/**
 * POST /webhooks/app-uninstalled
 * Called by Shopify when the app is removed from the store.
 * Validates the Shopify webhook HMAC before doing anything.
 */
app.post('/webhooks/app-uninstalled', (req, res) => {
  const signature = req.headers['x-shopify-hmac-sha256'];
  const shopDomain = req.headers['x-shopify-shop-domain'];

  if (!signature || !req.rawBody) {
    return res.status(400).send('Bad request.');
  }

  if (!validateWebhookHmac(req.rawBody, signature)) {
    console.warn(`[webhook] HMAC validation failed for uninstall from: ${shopDomain}`);
    return res.status(401).send('Unauthorized.');
  }

  console.log(`[webhook] App uninstalled from: ${shopDomain}`);
  revokeToken(shopDomain);
  res.status(200).send('OK');
});

/**
 * GET /sse
 * MCP Server-Sent Events endpoint.
 * Claude Desktop connects here to establish a persistent MCP session.
 *
 * Protected by: rateLimitMcp + bearerAuth
 * A fresh MCP Server + SSEServerTransport is created per connection.
 */
app.get('/sse', rateLimitMcp, bearerAuth, async (req, res) => {
  // Enforce session cap to prevent memory exhaustion
  if (Object.keys(transports).length >= MAX_SESSIONS) {
    console.warn('[mcp] Session cap reached, rejecting new connection from', req.ip);
    return res.status(503).json({ error: 'Server at capacity. Try again shortly.' });
  }

  console.log(`[mcp] New SSE connection | ip=${req.ip} | sessions=${Object.keys(transports).length + 1}`);

  const server = createMCPServer();
  const transport = new SSEServerTransport('/messages', res);

  transports[transport.sessionId] = transport;

  // Clean up when the client disconnects
  res.on('close', () => {
    console.log(`[mcp] SSE closed | session=${transport.sessionId}`);
    delete transports[transport.sessionId];
  });

  try {
    await server.connect(transport);
  } catch (err) {
    console.error('[mcp] Transport connect error:', err.message);
    delete transports[transport.sessionId];
  }
});

/**
 * POST /messages
 * MCP clients post tool call messages here.
 * Routes to the correct in-memory SSEServerTransport via `?sessionId=`.
 *
 * Protected by: bearerAuth (same token as /sse)
 */
app.post('/messages', bearerAuth, async (req, res) => {
  const { sessionId } = req.query;

  if (!sessionId) {
    return res.status(400).json({ error: 'Missing sessionId query parameter.' });
  }

  const transport = transports[sessionId];
  if (!transport) {
    console.warn(`[mcp] Unknown sessionId: ${sessionId}`);
    return res.status(404).json({ error: 'No active MCP session found.' });
  }

  try {
    await transport.handlePostMessage(req, res);
  } catch (err) {
    // Don't expose internal error details
    console.error('[mcp] Message handling error:', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});
// ─── REST Search API ──────────────────────────────────────────────────────────
// Simple HTTP endpoint so external tools can query Shopify without SSE.
// GET /api/search?q=QUERY&limit=5   — keyword/SKU/brand search
// GET /api/search?handle=HANDLE     — fetch single product by URL handle
// Protected by the same Bearer token as /sse.
app.get('/api/search', bearerAuth, async (req, res) => {
  const accessToken = getAccessToken(SHOP);
  if (!accessToken) {
    return res.status(503).json({ error: 'Shopify not connected. Visit /auth to install.' });
  }
  const { q, handle, limit: limitParam } = req.query;
  const limit = Math.min(parseInt(limitParam || '5', 10), 10);
  if (!q && !handle) {
    return res.status(400).json({ error: 'Provide q (search query) or handle (product handle).' });
  }
  try {
    const client = new ShopifyClient(SHOP, accessToken);
    if (handle) {
      const data = await client.getProductByHandle(handle.toString());
      const p = data?.productByHandle;
      return res.json({ products: p ? [fmt(p)] : [] });
    }
    const data = await client.searchProducts(q.toString(), limit);
    const products = (data?.products?.edges || []).map(e => fmt(e.node));
    res.json({ products, total: products.length });
  } catch (err) {
    console.error('[api/search] error:', err.message);
    res.status(500).json({ error: 'Search failed.' });
  }
});

function fmt(p) {
  return {
    id: p.id, title: p.title, handle: p.handle,
    url: `https://thelightingshoppe.ca/products/${p.handle}`,
    vendor: p.vendor, productType: p.productType,
    totalInventory: p.totalInventory,
    priceMin: p.priceRangeV2?.minVariantPrice?.amount,
    priceMax: p.priceRangeV2?.maxVariantPrice?.amount,
    currency: p.priceRangeV2?.minVariantPrice?.currencyCode,
    image: p.images?.edges?.[0]?.node?.url || null,
    variants: (p.variants?.edges || []).map(e => ({
      sku: e.node.sku, title: e.node.title,
      price: e.node.price, compareAtPrice: e.node.compareAtPrice,
      inventory: e.node.inventoryQuantity, available: e.node.availableForSale,
    })),
  };
}
// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ─── Global Error Handler ────────────────────────────────────────────────────
// Catches any unhandled errors thrown by route handlers.
// Returns a generic message in production; detailed message in dev.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('[server] Unhandled error:', err.message);
  res.status(500).json({
    error: IS_PROD ? 'Internal server error.' : err.message,
  });
});

// ─── Start Server ────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║       Lighting Shoppe MCP — Server Started       ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`  Port:        ${PORT}`);
  console.log(`  Shop:        ${SHOP}`);
  console.log(`  Host:        ${process.env.HOST}`);
  console.log(`  Installed:   ${isInstalled(SHOP) ? '✅ Yes' : '❌ No — visit /auth'}`);
  console.log(`  Bearer Auth: ✅ Enabled on /sse and /messages`);
  console.log(`  Helmet:      ✅ Security headers active`);
  console.log(`  Rate Limits: ✅ General / Auth / MCP`);
  console.log('');
});

// ─── HTML Helpers ────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function successPage(shop, host) {
  const sseUrl = `${host}/sse`;
  const configJson = JSON.stringify(
    {
      mcpServers: {
        'lighting-shoppe': {
          url: sseUrl,
          headers: {
            Authorization: 'Bearer YOUR_MCP_BEARER_TOKEN_HERE',
          },
        },
      },
    },
    null,
    2
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lighting Shoppe MCP — Connected</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           max-width: 700px; margin: 60px auto; padding: 0 24px; color: #1a1a2e; }
    h1   { color: #16213e; }
    code { background: #f4f6f9; border: 1px solid #dde3ef; border-radius: 4px;
           padding: 2px 6px; font-size: 0.9em; }
    pre  { background: #f4f6f9; border: 1px solid #dde3ef; border-radius: 8px;
           padding: 16px; overflow-x: auto; font-size: 0.85em; }
    .badge { display: inline-block; background: #22c55e; color: white;
             padding: 4px 14px; border-radius: 999px; font-size: 0.85em;
             font-weight: 600; margin-bottom: 16px; }
    .warn  { background: #fef9c3; border: 1px solid #fde047; border-radius: 8px;
             padding: 12px 16px; font-size: 0.9em; margin: 16px 0; }
    ol li  { margin-bottom: 8px; }
    a      { color: #2563eb; }
  </style>
</head>
<body>
  <span class="badge">✅ Connected</span>
  <h1>Lighting Shoppe MCP</h1>
  <p><strong>${escapeHtml(shop)}</strong> is now linked to Claude Desktop via the Model Context Protocol.</p>

  <h2>Connect Claude Desktop</h2>
  <div class="warn">
    ⚠️ Replace <code>YOUR_MCP_BEARER_TOKEN_HERE</code> below with the value of
    <code>MCP_BEARER_TOKEN</code> from your Railway environment variables.
  </div>
  <ol>
    <li>Open Claude Desktop → <strong>Settings → Developer → Edit Config</strong></li>
    <li>Add the following to <code>claude_desktop_config.json</code>:</li>
  </ol>
  <pre>${escapeHtml(configJson)}</pre>
  <ol start="3">
    <li>Save the file and <strong>restart Claude Desktop</strong>.</li>
    <li>Look for the 🔌 icon — you should see <strong>lighting-shoppe</strong> listed.</li>
  </ol>

  <h2>Available Tools</h2>
  <ul>
    <li><code>search_products</code> — full-text search the catalogue</li>
    <li><code>get_product_by_name</code> — look up a product by title</li>
    <li><code>check_inventory</code> — live stock levels by location</li>
    <li><code>get_pricing</code> — detailed pricing &amp; variant breakdown</li>
  </ul>

  <p style="margin-top:32px;color:#666;font-size:0.85em">
    MCP endpoint: <code>${escapeHtml(sseUrl)}</code> (Bearer token required)
  </p>
</body>
</html>`;
}

function errorPage(message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Lighting Shoppe MCP — Error</title>
  <style>
    body { font-family: sans-serif; padding: 40px; max-width: 600px; margin: auto; }
  </style>
</head>
<body>
  <h1>⚠️ Error</h1>
  <p>${escapeHtml(message)}</p>
  <p><a href="/auth">Try again</a></p>
</body>
</html>`;
}
