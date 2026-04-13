/**
 * mcp.js
 * Model Context Protocol server for The Lighting Shoppe.
 *
 * Exposes four tools to Claude Desktop:
 *   - search_products      → full-text product search
 *   - get_product_by_name  → find a product by title
 *   - check_inventory      → live stock levels by location
 *   - get_pricing          → detailed pricing & variant breakdown
 *
 * Transport: SSE (Server-Sent Events) over HTTP, suitable for remote hosting on Railway.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { ShopifyClient } from './shopify.js';
import { getAccessToken } from './auth.js';

const SHOP = process.env.SHOPIFY_SHOP || 'tzr7sd-ii.myshopify.com';

/**
 * Get an authenticated Shopify client for our store.
 * Throws if OAuth has not been completed yet.
 */
function getClient() {
  const token = getAccessToken(SHOP);
  if (!token) {
    throw new Error(
      `The Lighting Shoppe (${SHOP}) is not yet authenticated. ` +
        `Please visit ${process.env.HOST || 'http://localhost:3000'}/auth to install the app.`
    );
  }
  return new ShopifyClient(SHOP, token);
}

// ─── Tool Definitions ────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: 'search_products',
    description:
      'Search The Lighting Shoppe\'s Shopify catalogue for lighting products by keyword, ' +
      'category, finish, or any product attribute. Returns product names, pricing, ' +
      'inventory status, and Shopify product IDs needed for other tools.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description:
            'Search query. Supports plain text (e.g. "pendant light") or Shopify search ' +
            'syntax (e.g. "product_type:chandelier", "vendor:Kichler", "tag:LED").',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of products to return. Default: 10. Maximum: 25.',
          minimum: 1,
          maximum: 25,
          default: 10,
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'get_product_by_name',
    description:
      'Find a specific lighting product by its name or title. ' +
      'Use this when you know roughly what the product is called, ' +
      'e.g. "Mirage pendant", "Kichler Telford", "WAC 6-inch pot light".',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'The product name or title to look up.',
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'check_inventory',
    description:
      'Check live inventory/stock levels for a specific product, broken down by variant ' +
      '(finish, size, colour) and by warehouse/location. ' +
      'Use the Shopify product ID returned by search_products or get_product_by_name.',
    inputSchema: {
      type: 'object',
      properties: {
        product_id: {
          type: 'string',
          description:
            'Shopify Global ID for the product, e.g. "gid://shopify/Product/1234567890".',
        },
      },
      required: ['product_id'],
    },
  },
  {
    name: 'get_pricing',
    description:
      'Get detailed pricing for a specific product, including the retail price, ' +
      'compare-at (was) price, and per-variant breakdown for all finishes/sizes. ' +
      'Useful for preparing quotes. ' +
      'Use the Shopify product ID returned by search_products or get_product_by_name.',
    inputSchema: {
      type: 'object',
      properties: {
        product_id: {
          type: 'string',
          description:
            'Shopify Global ID for the product, e.g. "gid://shopify/Product/1234567890".',
        },
      },
      required: ['product_id'],
    },
  },
];

// ─── MCP Server Factory ──────────────────────────────────────────────────────

/**
 * Create and configure a new MCP Server instance.
 * A fresh instance is created per SSE connection.
 */
export function createMCPServer() {
  const server = new Server(
    {
      name: 'lighting-shoppe-mcp',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // ── List available tools ─────────────────────────────────────────────────
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // ── Handle tool calls ────────────────────────────────────────────────────
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    try {
      const client = getClient();

      switch (name) {
        // ──────────────────────────────────────────────────────────────────
        case 'search_products': {
          const { query, limit = 10 } = args;
          if (!query || typeof query !== 'string') {
            throw new Error('`query` is required and must be a string.');
          }

          const data = await client.searchProducts(query, limit);
          const products = data.products.edges;

          if (products.length === 0) {
            return text(
              `No products found for "${query}" in The Lighting Shoppe catalogue.\n\n` +
                `Try a broader search term or check the product type (e.g. "pendant", "chandelier", "pot light").`
            );
          }

          const lines = [
            `Found **${products.length}** product(s) matching "${query}":\n`,
          ];

          for (const { node } of products) {
            lines.push(formatProductSummary(node));
            lines.push('---');
          }

          if (data.products.pageInfo?.hasNextPage) {
            lines.push(
              `\n*More results available. Increase \`limit\` or refine your search.*`
            );
          }

          return text(lines.join('\n'));
        }

        // ──────────────────────────────────────────────────────────────────
        case 'get_product_by_name': {
          const { name: productName } = args;
          if (!productName || typeof productName !== 'string') {
            throw new Error('`name` is required and must be a string.');
          }

          const data = await client.getProductByTitle(productName);
          const products = data.products.edges;

          if (products.length === 0) {
            return text(
              `No products found matching "${productName}".\n\n` +
                `This product may not be in the Shopify catalogue — try search_products with a broader query.`
            );
          }

          const lines = [
            `Found **${products.length}** product(s) matching "${productName}":\n`,
          ];
          for (const { node } of products) {
            lines.push(formatProductSummary(node));
            lines.push('---');
          }

          return text(lines.join('\n'));
        }

        // ──────────────────────────────────────────────────────────────────
        case 'check_inventory': {
          const { product_id } = args;
          if (!product_id) throw new Error('`product_id` is required.');

          const data = await client.checkInventory(product_id);

          if (!data.product) {
            return text(
              `Product not found: \`${product_id}\`\n\n` +
                `Use search_products to look up the correct Shopify product ID.`
            );
          }

          return text(formatInventory(data.product));
        }

        // ──────────────────────────────────────────────────────────────────
        case 'get_pricing': {
          const { product_id } = args;
          if (!product_id) throw new Error('`product_id` is required.');

          const data = await client.getPricing(product_id);

          if (!data.product) {
            return text(
              `Product not found: \`${product_id}\`\n\n` +
                `Use search_products to look up the correct Shopify product ID.`
            );
          }

          return text(formatPricing(data.product));
        }

        // ──────────────────────────────────────────────────────────────────
        default:
          throw new Error(`Unknown tool: "${name}"`);
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ─── Formatting Helpers ──────────────────────────────────────────────────────

function text(str) {
  return { content: [{ type: 'text', text: str }] };
}

function stockLabel(qty) {
  if (qty === null || qty === undefined) return 'Unknown';
  if (qty <= 0) return '🔴 Out of Stock';
  if (qty < 5) return `🟡 Low Stock (${qty})`;
  return `🟢 In Stock (${qty})`;
}

function formatProductSummary(p) {
  const currency = p.priceRangeV2?.minVariantPrice?.currencyCode || 'CAD';
  const minPrice = parseFloat(p.priceRangeV2?.minVariantPrice?.amount || 0).toFixed(2);
  const maxPrice = parseFloat(p.priceRangeV2?.maxVariantPrice?.amount || 0).toFixed(2);
  const priceStr =
    minPrice === maxPrice ? `$${minPrice} ${currency}` : `$${minPrice}–$${maxPrice} ${currency}`;

  const lines = [
    `**${p.title}**`,
    `  ID: \`${p.id}\``,
    `  Status: ${p.status}`,
    `  Price: ${priceStr}`,
    `  Total Inventory: ${p.totalInventory !== null ? p.totalInventory : 'Not tracked'}`,
  ];

  if (p.productType) lines.push(`  Type: ${p.productType}`);
  if (p.vendor) lines.push(`  Vendor: ${p.vendor}`);
  if (p.onlineStoreUrl) lines.push(`  URL: ${p.onlineStoreUrl}`);

  const variants = p.variants?.edges || [];
  if (variants.length > 1) {
    lines.push(`  Variants (${variants.length}):`);
    for (const { node: v } of variants) {
      const opts = v.selectedOptions?.map((o) => `${o.name}: ${o.value}`).join(', ') || v.title;
      const disc = v.compareAtPrice && parseFloat(v.compareAtPrice) > parseFloat(v.price)
        ? ` ~~$${parseFloat(v.compareAtPrice).toFixed(2)}~~`
        : '';
      lines.push(
        `    • ${opts} — $${parseFloat(v.price).toFixed(2)}${disc} | ${stockLabel(v.inventoryQuantity)}${v.sku ? ` | SKU: ${v.sku}` : ''}`
      );
    }
  } else if (variants.length === 1) {
    const v = variants[0].node;
    if (v.sku) lines.push(`  SKU: ${v.sku}`);
  }

  return lines.join('\n');
}

function formatInventory(product) {
  const lines = [
    `## Inventory: ${product.title}`,
    `**ID:** \`${product.id}\``,
    `**Status:** ${product.status}`,
    `**Total Stock:** ${product.totalInventory !== null ? product.totalInventory : 'Not tracked'}`,
    '',
  ];

  const variants = product.variants?.edges || [];

  for (const { node: v } of variants) {
    const opts =
      v.selectedOptions?.map((o) => `${o.name}: ${o.value}`).join(', ') || v.title;
    lines.push(`### ${opts}${v.sku ? ` (SKU: ${v.sku})` : ''}`);
    lines.push(`  Overall Quantity: ${v.inventoryQuantity !== null ? v.inventoryQuantity : 'N/A'}`);
    lines.push(`  Available for Sale: ${v.availableForSale ? 'Yes' : 'No'}`);

    const unitCost = v.inventoryItem?.unitCost;
    if (unitCost?.amount) {
      lines.push(`  Cost: $${parseFloat(unitCost.amount).toFixed(2)} ${unitCost.currencyCode}`);
    }

    const levels = v.inventoryItem?.inventoryLevels?.edges || [];
    if (levels.length > 0) {
      lines.push('  By Location:');
      for (const { node: lvl } of levels) {
        const loc = lvl.location;
        const locName = loc?.address?.city
          ? `${loc.name} (${loc.address.city}, ${loc.address.province})`
          : loc?.name || 'Unknown';
        lines.push(`    • ${locName}: **${lvl.available}** available`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

function formatPricing(product) {
  const currency =
    product.priceRangeV2?.minVariantPrice?.currencyCode || 'CAD';

  const lines = [
    `## Pricing: ${product.title}`,
    `**ID:** \`${product.id}\`  |  **Vendor:** ${product.vendor || 'N/A'}  |  **Type:** ${product.productType || 'N/A'}`,
    `**Status:** ${product.status}`,
    '',
    `**Price Range:** $${parseFloat(product.priceRangeV2.minVariantPrice.amount).toFixed(2)}–$${parseFloat(product.priceRangeV2.maxVariantPrice.amount).toFixed(2)} ${currency}`,
    '',
    '### Variants',
  ];

  const variants = product.variants?.edges || [];

  for (const { node: v } of variants) {
    const opts =
      v.selectedOptions?.map((o) => `${o.name}: ${o.value}`).join(', ') || v.title;
    const price = parseFloat(v.price).toFixed(2);
    const hasDiscount =
      v.compareAtPrice && parseFloat(v.compareAtPrice) > parseFloat(v.price);
    const compareAt = hasDiscount
      ? ` ~~$${parseFloat(v.compareAtPrice).toFixed(2)}~~ (save $${(parseFloat(v.compareAtPrice) - parseFloat(v.price)).toFixed(2)})`
      : '';

    lines.push(`**${opts}**`);
    lines.push(`  Price: $${price} ${currency}${compareAt}`);

    const unitCost = v.inventoryItem?.unitCost;
    if (unitCost?.amount) {
      const cost = parseFloat(unitCost.amount);
      const retail = parseFloat(v.price);
      const margin = retail > 0 ? (((retail - cost) / retail) * 100).toFixed(1) : null;
      const markup = cost > 0 ? (((retail - cost) / cost) * 100).toFixed(1) : null;
      lines.push(`  Cost: $${cost.toFixed(2)} ${unitCost.currencyCode}`);
      if (margin !== null) lines.push(`  Margin: ${margin}%  |  Markup: ${markup}%`);
    }

    if (v.sku) lines.push(`  SKU: ${v.sku}`);
    lines.push(`  Taxable: ${v.taxable ? 'Yes' : 'No'}`);
    lines.push(`  Available: ${v.availableForSale ? 'Yes' : 'No'}`);
    lines.push('');
  }

  return lines.join('\n');
}

// Re-export SSEServerTransport so index.js only needs to import from here
export { SSEServerTransport };
