/**
 * NFA Reseller API Proxy — Cloudflare Worker
 * 
 * Secrets (set via `wrangler secret put`):
 *   NFA_API_KEY      — your NFA reseller API key
 *   PANEL_AUTH_TOKEN  — password users enter in the panel UI
 */

const NFA_ORIGIN = 'https://nfa-api.acode.ing';

// Allowed origins — add your domain(s) here.
// 'null' origin covers local file:// access for development.
// Leave empty to allow all origins.
const ALLOWED_ORIGINS = new Set([
  '*'
]);

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Panel-Auth',
    'Access-Control-Max-Age': '86400',
  };
}

function forbidden(msg, origin) {
  return new Response(JSON.stringify({ status: 'error', message: msg }), {
    status: 403,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

function badRequest(msg, origin) {
  return new Response(JSON.stringify({ status: 'error', message: msg }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || 'null';

    // --- CORS preflight ---
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // --- Origin check (skip if ALLOWED_ORIGINS is empty / contains wildcard) ---
    if (ALLOWED_ORIGINS.size > 0 && !ALLOWED_ORIGINS.has('*')) {
      // Allow 'null' origin for local file:// during development
      if (!ALLOWED_ORIGINS.has(origin) && origin !== 'null') {
        return forbidden('Origin not allowed', origin);
      }
    }

    // --- Panel auth check ---
    if (env.PANEL_AUTH_TOKEN) {
      const isPublic = url.pathname.endsWith('/create_exe') || url.pathname.endsWith('/activate');
      if (!isPublic) {
        const token = request.headers.get('X-Panel-Auth') || '';
        if (token !== env.PANEL_AUTH_TOKEN) {
          return forbidden('Invalid panel authentication', origin);
        }
      }
    }

    // --- Only proxy /api/v1/* paths ---
    if (!url.pathname.startsWith('/api/v1/')) {
      return badRequest('Only /api/v1/* paths are proxied', origin);
    }

    // --- Build upstream request ---
    const upstream = new URL(url.pathname + url.search, NFA_ORIGIN);

    if (!env.NFA_API_KEY) {
      return new Response(JSON.stringify({ status: 'error', message: 'Server configuration error: NFA_API_KEY is not set in Cloudflare' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const headers = new Headers();
    headers.set('X-API-Key', env.NFA_API_KEY);
    headers.set('Content-Type', 'application/json');
    headers.set('Accept', 'application/json');

    const init = {
      method: request.method,
      headers,
    };

    // Forward body for POST/PUT/DELETE
    if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
      const body = await request.text();
      if (body) init.body = body;
    }

    try {
      const response = await fetch(upstream.toString(), init);

      // Clone response with CORS headers
      const responseHeaders = new Headers(response.headers);
      Object.entries(corsHeaders(origin)).forEach(([k, v]) => responseHeaders.set(k, v));

      // Strip any server-side headers that might leak info
      responseHeaders.delete('Server');
      responseHeaders.delete('X-Powered-By');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(JSON.stringify({ status: 'error', message: 'Upstream request failed: ' + err.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  },
};
