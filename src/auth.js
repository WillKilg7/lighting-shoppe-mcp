/**
 * auth.js
 * Shopify OAuth 2.0 Authorization Code Grant flow for The Lighting Shoppe MCP.
 *
 * Security features:
 *  - CSRF protection via random state parameter
 *  - HMAC validation on every OAuth callback
 *  - Timing-safe comparison to prevent timing attacks
 *  - Tokens stored in a file with 0600 permissions (never logged)
 *  - Pending states expire after 10 minutes
 */

import crypto from 'crypto';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Token storage: flat JSON file in project root, permissions locked to owner only.
// In a production multi-tenant scenario, replace with an encrypted database.
const TOKEN_FILE = path.join(__dirname, '..', '.tokens.json');

// In-memory token store (loaded from file at startup)
const tokenStore = new Map();

// Pending OAuth states keyed by state string (CSRF protection)
const pendingStates = new Map();

// ─── Token Persistence ─────────────────────────────────────────────────────

/**
 * Load persisted tokens from disk on startup.
 * Tokens are never logged.
 */
export function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const raw = fs.readFileSync(TOKEN_FILE, 'utf-8');
      const data = JSON.parse(raw);
      for (const [shop, token] of Object.entries(data)) {
        tokenStore.set(shop, token);
      }
      console.log(`[auth] Loaded tokens for ${tokenStore.size} shop(s).`);
    }
  } catch (err) {
    console.error('[auth] Failed to load tokens:', err.message);
  }
}

/**
 * Persist token store to disk.
 * File is written with mode 0o600 so only the process owner can read it.
 */
function saveTokens() {
  try {
    const data = Object.fromEntries(tokenStore);
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
  } catch (err) {
    console.error('[auth] Failed to save tokens:', err.message);
  }
}

// Load tokens immediately when this module is first imported
loadTokens();

// ─── OAuth Flow ─────────────────────────────────────────────────────────────

/**
 * Build the Shopify OAuth authorization URL and register a CSRF state token.
 *
 * @param {string} shop  e.g. "tzr7sd-ii.myshopify.com"
 * @returns {{ url: string, state: string }}
 */
export function generateAuthUrl(shop) {
  // Generate a random 32-character hex state token
  const state = crypto.randomBytes(16).toString('hex');

  // Register the state with an expiry timestamp
  pendingStates.set(state, { shop, createdAt: Date.now() });

  // Purge any states older than 10 minutes
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [s, meta] of pendingStates.entries()) {
    if (meta.createdAt < tenMinutesAgo) {
      pendingStates.delete(s);
    }
  }

  const params = new URLSearchParams({
    client_id: process.env.SHOPIFY_CLIENT_ID,
    scope: process.env.SHOPIFY_SCOPES || 'read_products,read_inventory,read_orders',
    redirect_uri: `${process.env.HOST}/auth/callback`,
    state,
  });

  return {
    url: `https://${shop}/admin/oauth/authorize?${params.toString()}`,
    state,
  };
}

/**
 * Handle the OAuth callback:
 *  1. Validate the state parameter (CSRF check)
 *  2. Validate the HMAC signature from Shopify
 *  3. Exchange the code for an access token
 *  4. Persist the token securely
 *
 * @param {string} shop   The shop domain from the callback query string
 * @param {string} code   The authorization code from Shopify
 * @param {string} state  The state token echoed back by Shopify
 * @param {string} hmac   The HMAC provided by Shopify for validation
 * @param {object} query  The full parsed query-string object (for HMAC validation)
 * @returns {Promise<string>} The access token (for internal use — never returned to the user)
 */
export async function handleCallback(shop, code, state, hmac, query) {
  // 1. CSRF: verify state exists and hasn't expired
  if (!pendingStates.has(state)) {
    throw new Error('Invalid or expired OAuth state parameter. Please restart the auth flow.');
  }

  const pendingMeta = pendingStates.get(state);
  pendingStates.delete(state); // consume it immediately

  // Ensure the shop in the callback matches the one that initiated the flow
  if (pendingMeta.shop !== shop) {
    throw new Error('Shop domain mismatch between auth request and callback.');
  }

  // 2. HMAC validation
  if (!validateHmac(hmac, query)) {
    throw new Error('HMAC validation failed. The callback may have been tampered with.');
  }

  // 3. Exchange authorization code for a permanent access token
  const tokenResponse = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.SHOPIFY_CLIENT_ID,
      client_secret: process.env.SHOPIFY_CLIENT_SECRET,
      code,
    }),
  });

  if (!tokenResponse.ok) {
    throw new Error(`Token exchange failed: ${tokenResponse.status} ${tokenResponse.statusText}`);
  }

  const tokenData = await tokenResponse.json();

  if (!tokenData.access_token) {
    throw new Error('Shopify did not return an access token.');
  }

  // 4. Persist token — never log it
  tokenStore.set(shop, tokenData.access_token);
  saveTokens();

  console.log(`[auth] Access token stored for shop: ${shop}`);

  // Return scope info (safe to log/display) but NOT the token itself
  return {
    shop,
    scope: tokenData.scope,
  };
}

// ─── HMAC Validation ────────────────────────────────────────────────────────

/**
 * Validate the HMAC signature Shopify sends with every OAuth callback.
 * Per Shopify docs: remove `hmac` from params, sort alphabetically,
 * join as `key=value&key=value`, then HMAC-SHA256 with the client secret.
 *
 * @param {string} hmac  The hmac value from the query string
 * @param {object|URLSearchParams} queryParams  The full query object
 * @returns {boolean}
 */
export function validateHmac(hmac, queryParams) {
  // Build a mutable copy
  const params =
    queryParams instanceof URLSearchParams
      ? new URLSearchParams(queryParams)
      : new URLSearchParams(queryParams);

  params.delete('hmac');

  // Sort entries alphabetically by key and build the message string
  const message = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');

  const expectedHmac = crypto
    .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
    .update(message)
    .digest('hex');

  // Timing-safe comparison prevents timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(hmac.padEnd(expectedHmac.length, '\0'), 'hex'),
      Buffer.from(expectedHmac, 'hex')
    );
  } catch {
    // Buffer sizes won't match if hmac is malformed — treat as invalid
    return false;
  }
}

/**
 * Validate a Shopify webhook HMAC signature.
 * Used for incoming webhook payloads (X-Shopify-Hmac-Sha256 header).
 *
 * @param {string} rawBody   The raw request body string
 * @param {string} signature The base64-encoded HMAC from the request header
 * @returns {boolean}
 */
export function validateWebhookHmac(rawBody, signature) {
  const expectedDigest = crypto
    .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
    .update(rawBody, 'utf-8')
    .digest('base64');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'base64'),
      Buffer.from(expectedDigest, 'base64')
    );
  } catch {
    return false;
  }
}

// ─── Token Accessors ────────────────────────────────────────────────────────

/**
 * Retrieve the stored access token for a shop.
 * Returns undefined if not installed.
 */
export function getAccessToken(shop) {
  return tokenStore.get(shop);
}

/**
 * Check whether a shop has completed OAuth installation.
 */
export function isInstalled(shop) {
  return tokenStore.has(shop);
}

/**
 * Remove a shop's token (e.g. after an app/uninstalled webhook).
 */
export function revokeToken(shop) {
  tokenStore.delete(shop);
  saveTokens();
  console.log(`[auth] Token revoked for shop: ${shop}`);
}
