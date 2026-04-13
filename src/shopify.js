/**
 * shopify.js
 * Shopify Admin GraphQL API client for The Lighting Shoppe.
 * Handles all product, inventory, and pricing queries.
 * Never logs access tokens or secrets.
 */

import fetch from 'node-fetch';

const SHOPIFY_API_VERSION = '2024-04';

export class ShopifyClient {
  constructor(shop, accessToken) {
    this.shop = shop;
    // Store token without logging it
    this._accessToken = accessToken;
    this.endpoint = `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  }

  /**
   * Execute a GraphQL query against the Shopify Admin API.
   */
  async query(graphqlQuery, variables = {}) {
    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': this._accessToken,
      },
      body: JSON.stringify({ query: graphqlQuery, variables }),
    });

    if (!response.ok) {
      throw new Error(`Shopify API error: ${response.status} ${response.statusText}`);
    }

    const json = await response.json();

    if (json.errors && json.errors.length > 0) {
      const messages = json.errors.map((e) => e.message).join('; ');
      throw new Error(`Shopify GraphQL error: ${messages}`);
    }

    return json.data;
  }

  /**
   * Search products by keyword. Returns up to `limit` results.
   * Supports Shopify search syntax, e.g. "title:pendant", "product_type:chandelier"
   */
  async searchProducts(searchQuery, limit = 10) {
    const gql = `
      query SearchProducts($query: String!, $first: Int!) {
        products(first: $first, query: $query) {
          edges {
            node {
              id
              title
              handle
              status
              productType
              vendor
              tags
              description: descriptionHtml
              onlineStoreUrl
              priceRangeV2 {
                minVariantPrice {
                  amount
                  currencyCode
                }
                maxVariantPrice {
                  amount
                  currencyCode
                }
              }
              totalInventory
              variants(first: 20) {
                edges {
                  node {
                    id
                    title
                    sku
                    price
                    compareAtPrice
                    inventoryQuantity
                    availableForSale
                    selectedOptions {
                      name
                      value
                    }
                    inventoryItem {
                      unitCost {
                        amount
                        currencyCode
                      }
                    }
                  }
                }
              }
              images(first: 1) {
                edges {
                  node {
                    url
                    altText
                  }
                }
              }
            }
          }
          pageInfo {
            hasNextPage
          }
        }
      }
    `;
    return this.query(gql, { query: searchQuery, first: Math.min(limit, 25) });
  }

  /**
   * Find a product by its exact or approximate title.
   */
  async getProductByTitle(title) {
    return this.searchProducts(`title:${title}`, 5);
  }

  /**
   * Get detailed inventory levels for a specific product by its Shopify GID.
   */
  async checkInventory(productId) {
    const gql = `
      query CheckInventory($id: ID!) {
        product(id: $id) {
          id
          title
          handle
          status
          totalInventory
          tracksInventory
          variants(first: 30) {
            edges {
              node {
                id
                title
                sku
                inventoryQuantity
                availableForSale
                inventoryItem {
                  id
                  tracked
                  unitCost {
                    amount
                    currencyCode
                  }
                  inventoryLevels(first: 10) {
                    edges {
                      node {
                        available
                        location {
                          id
                          name
                          address {
                            city
                            province
                            country
                          }
                        }
                      }
                    }
                  }
                }
                selectedOptions {
                  name
                  value
                }
              }
            }
          }
        }
      }
    `;
    return this.query(gql, { id: productId });
  }

  /**
   * Get detailed pricing for a specific product, including all variants and compare-at prices.
   */
  async getPricing(productId) {
    const gql = `
      query GetPricing($id: ID!) {
        product(id: $id) {
          id
          title
          handle
          status
          vendor
          productType
          priceRangeV2 {
            minVariantPrice {
              amount
              currencyCode
            }
            maxVariantPrice {
              amount
              currencyCode
            }
          }
          compareAtPriceRange {
            minVariantCompareAtPrice {
              amount
              currencyCode
            }
            maxVariantCompareAtPrice {
              amount
              currencyCode
            }
          }
          variants(first: 30) {
            edges {
              node {
                id
                title
                sku
                price
                compareAtPrice
                taxable
                availableForSale
                selectedOptions {
                  name
                  value
                }
                inventoryItem {
                  unitCost {
                    amount
                    currencyCode
                  }
                }
              }
            }
          }
        }
      }
    `;
    return this.query(gql, { id: productId });
  }

  /**
   * Get a product by its handle (URL slug).
   */
  async getProductByHandle(handle) {
    const gql = `
      query GetProductByHandle($handle: String!) {
        productByHandle(handle: $handle) {
          id
          title
          handle
          status
          priceRangeV2 {
            minVariantPrice {
              amount
              currencyCode
            }
            maxVariantPrice {
              amount
              currencyCode
            }
          }
          totalInventory
          variants(first: 20) {
            edges {
              node {
                id
                title
                sku
                price
                compareAtPrice
                inventoryQuantity
                availableForSale
                selectedOptions {
                  name
                  value
                }
                inventoryItem {
                  unitCost {
                    amount
                    currencyCode
                  }
                }
              }
            }
          }
        }
      }
    `;
    return this.query(gql, { handle });
  }
}
