# Lighting Shoppe MCP

A Shopify OAuth app that exposes The Lighting Shoppe's live product pricing and inventory to **Claude Desktop** via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

Once deployed, Claude can answer questions like:

> *"How many WAC pot lights do we have in stock?"*
> *"What's the current price on the Kichler Telford pendant?"*
> *"Give me a quote for 12× the Mirage 5CCT pot light."*

---

## Architecture

```
Claude Desktop
     │  MCP (SSE over HTTPS)
     ▼
Railway App (this server)
  ├── Express.js
  ├── Shopify OAuth 2.0 (Authorization Code Grant)
  └── Shopify Admin GraphQL API
           │
           ▼
   tzr7sd-ii.myshopify.com
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| Node.js | ≥ 18.0.0 |
| npm | ≥ 9 |
| Shopify CLI | 3.x (already installed) |
| Railway account | [railway.app](https://railway.app) |
| Shopify Partner account | [partners.shopify.com](https://partners.shopify.com) |

---

## Step 1 — Create the Shopify App

1. Go to [partners.shopify.com](https://partners.shopify.com) → **Apps → Create app**.
2. Choose **Create app manually**.
3. Name it `Lighting Shoppe MCP`.
4. Under **App setup → URLs**, set:
   - **App URL:** `https://your-railway-app.up.railway.app`
   - **Allowed redirection URL(s):** `https://your-railway-app.up.railway.app/auth/callback`
5. Copy your **Client ID** and **Client Secret** — you'll need them in Step 3.

---

## Step 2 — Deploy to Railway

### Option A: Deploy from GitHub (recommended)

1. Push this folder to a new GitHub repository:
   ```bash
   cd lighting-shoppe-mcp
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/lighting-shoppe-mcp.git
   git push -u origin main
   ```

2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo**.
3. Select your `lighting-shoppe-mcp` repo.
4. Railway will auto-detect Node.js and deploy.

### Option B: Deploy with Railway CLI

```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

### Get your Railway URL

After deploying, Railway gives you a URL like:
```
https://lighting-shoppe-mcp-production.up.railway.app
```

Go back to your Shopify Partner app and update the URLs (Step 1) with this real Railway URL.

---

## Step 3 — Configure Environment Variables

In Railway → your service → **Variables**, add:

| Variable | Value |
|----------|-------|
| `SHOPIFY_CLIENT_ID` | From Shopify Partner Dashboard |
| `SHOPIFY_CLIENT_SECRET` | From Shopify Partner Dashboard |
| `SHOPIFY_SCOPES` | `read_products,read_inventory,read_orders` |
| `SHOPIFY_SHOP` | `tzr7sd-ii.myshopify.com` |
| `HOST` | `https://your-railway-app.up.railway.app` |
| `SESSION_SECRET` | Run: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |

> ⚠️ **Never commit `.env` to Git.** The `.gitignore` already excludes it.

For local development, copy `.env.example` to `.env` and fill in the values:
```bash
cp .env.example .env
```

---

## Step 4 — Install the App on Your Store

1. Visit `https://your-railway-app.up.railway.app/auth` in your browser.
2. Shopify will ask you to authorize the app on `tzr7sd-ii.myshopify.com`.
3. Click **Install app**.
4. You'll be redirected back and see a green ✅ success page with the Claude Desktop config snippet.

---

## Step 5 — Connect to Claude Desktop

1. Open **Claude Desktop** → **Settings → Developer → Edit Config**.
2. Add the following to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "lighting-shoppe": {
      "url": "https://your-railway-app.up.railway.app/sse"
    }
  }
}
```

3. Save the file and **restart Claude Desktop**.
4. Look for the 🔌 plug icon — `lighting-shoppe` should appear as a connected tool.

---

## Available MCP Tools

Once connected, Claude Desktop has access to four tools:

### `search_products`
Full-text search across the entire Shopify catalogue.

```
query: "pendant light"    → finds all pendant lights
query: "vendor:Kichler"   → all Kichler products
query: "tag:LED"          → all products tagged LED
query: "product_type:chandelier"
```

### `get_product_by_name`
Find a specific product by its title.

```
name: "Mirage 5CCT Pot Light"
name: "Kichler Telford"
```

### `check_inventory`
Live stock levels by location for every variant.

```
product_id: "gid://shopify/Product/1234567890"
```

### `get_pricing`
Full pricing breakdown including compare-at (sale) prices for every variant.

```
product_id: "gid://shopify/Product/1234567890"
```

---

## Local Development

```bash
# Install dependencies
npm install

# Start the dev server (auto-restarts on file changes)
npm run dev
```

For OAuth to work locally, you need a public HTTPS URL. Use [ngrok](https://ngrok.com):
```bash
ngrok http 3000
```

Update `HOST` in `.env` and your Shopify app's redirect URL with the ngrok URL, then visit `http://localhost:3000/auth`.

---

## Security Notes

- **HMAC validation** on every OAuth callback prevents request forgery.
- **CSRF protection** via a random `state` parameter that expires after 10 minutes.
- **Timing-safe comparison** (`crypto.timingSafeEqual`) for all HMAC checks.
- **Access tokens** are never logged — only stored in `.tokens.json` with `0600` permissions.
- **Webhook HMAC** validation on the `app/uninstalled` endpoint.
- `.tokens.json` and `.env` are both excluded from Git via `.gitignore`.

---

## File Structure

```
lighting-shoppe-mcp/
├── src/
│   ├── index.js      # Express server — routes & SSE transport management
│   ├── auth.js       # Shopify OAuth flow, HMAC validation, token storage
│   ├── mcp.js        # MCP Server — tool definitions & handlers
│   └── shopify.js    # Shopify Admin GraphQL API client
├── .env.example      # Environment variable template
├── .gitignore
├── package.json
├── railway.toml      # Railway deployment config
└── README.md
```

---

## Troubleshooting

**"Shop is not authenticated" error in Claude**
→ Visit `https://your-railway-app.up.railway.app/auth` to re-install the app.

**OAuth callback fails with "Invalid HMAC"**
→ Double-check that `SHOPIFY_CLIENT_SECRET` in Railway matches your Partner Dashboard.

**Claude doesn't show the lighting-shoppe tool**
→ Confirm the `url` in `claude_desktop_config.json` ends in `/sse`, then restart Claude Desktop.

**Railway deploy fails**
→ Check that `NODE_VERSION` is ≥ 18. Set it in Railway Variables if needed: `NODE_VERSION=20`.

---

## Shopify API Reference

- [Admin GraphQL API](https://shopify.dev/docs/api/admin-graphql)
- [OAuth](https://shopify.dev/docs/apps/auth/oauth)
- [Product queries](https://shopify.dev/docs/api/admin-graphql/2024-04/queries/products)
