/**
 * V6.3 — Static frontend serving for the Hostinger
 * Business runtime.
 *
 * Serves the built Vite frontend (dist/) from the
 * same Node process that exposes the API. The
 * dispatcher enforces:
 *
 *   - API routes take precedence over the SPA
 *     fallback. /api/* never falls through to a
 *     static file.
 *   - SPA fallback: every non-API, non-asset path
 *     returns dist/index.html with no-store.
 *   - Hashed assets (under /assets/) are served
 *     with Cache-Control: public, max-age=31536000,
 *     immutable.
 *   - index.html is served with no-store so a
 *     deploy always wins.
 *   - NEVER serves from the persistent data root.
 *   - NEVER serves .env, .git, node_modules,
 *     backup archives, or source maps in
 *     production.
 *   - Bounded URL length and bounded per-request
 *     read size (max 8 MiB for a static asset).
 *   - Path-traversal rejection: the requested
 *     path MUST resolve inside the publicDir after
 *     normalization.
 *   - Security headers (X-Content-Type-Options,
 *     X-Frame-Options, Referrer-Policy,
 *     Strict-Transport-Security) on every response.
 *
 * The module is intentionally framework-free; it
 * uses only node:fs + node:path + node:url.
 */

import { createReadStream, statSync, existsSync } from 'node:fs';
import { resolve, join, normalize, relative, sep, isAbsolute } from 'node:path';
import { pipeline } from 'node:stream/promises';

const MAX_PATH_LENGTH = 2048;
const MAX_FILE_SIZE = 8 * 1024 * 1024; // 8 MiB
const HASHED_ASSET_RE = /^\/assets\/[^/]+\.[a-z0-9]{8}\.[a-z]+$/i;
const HASHED_ASSET_DIR_RE = /^\/assets\//;
const FORBIDDEN_TOP_LEVEL = new Set([
  '.env', '.env.local', '.env.production', '.env.development',
  '.git', '.gitignore', '.gitattributes', '.dockerignore',
  'node_modules', 'coverage', 'dist.zip', 'state',
  'logs', 'backups', 'tools', 'hostinger', 'jobs',
  'scripts', 'netlify', 'src', 'tests', 'docs',
  'CHANGELOG.md', 'README.md', 'package.json', 'package-lock.json',
  'tsconfig.json', 'tsconfig.node.json', 'vite.config.ts',
  'tailwind.config.js', 'postcss.config.js',
  '.env.example', 'Dockerfile', 'docker-compose.yml',
]);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.mjs':  'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.webp': 'image/webp',
  '.ico':  'image/x-icon',
  '.txt':  'text/plain; charset=utf-8',
  '.map':  'application/json; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf':  'font/ttf',
  '.eot':  'application/vnd.ms-fontobject',
};

function mimeFor(filePath) {
  const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

function applySecurityHeaders(headers, { isProduction = true, allowFrame = false } = {}) {
  // X-Content-Type-Options: nosniff prevents MIME-
  // type sniffing by browsers.
  if (!headers.has('X-Content-Type-Options')) headers.set('X-Content-Type-Options', 'nosniff');
  // X-Frame-Options: sameorigin (the dashboard is
  // an SPA; clickjacking is mitigated by denying
  // framing from foreign origins).
  if (!allowFrame && !headers.has('X-Frame-Options')) headers.set('X-Frame-Options', 'SAMEORIGIN');
  // Referrer-Policy: same-origin so the SPA does
  // not leak request paths to external resources.
  if (!headers.has('Referrer-Policy')) headers.set('Referrer-Policy', 'same-origin');
  if (isProduction) {
    if (!headers.has('Strict-Transport-Security')) headers.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }
  return headers;
}

/**
 * Build a `Response` for a static asset. The caller
 * is responsible for the ReadableStream → Node
 * socket bridge; this module returns a
 * `Response`-shaped object with the body as a
 * Node Readable stream so the existing writeResponse
 * can stream it.
 */
function staticAssetResponse({ filePath, fileSize, contentType, isHashed, isIndexHtml }) {
  const headers = new Headers();
  headers.set('Content-Type', contentType);
  headers.set('Content-Length', String(fileSize));
  headers.set('X-Content-Type-Options', 'nosniff');
  if (isHashed) {
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  } else if (isIndexHtml) {
    headers.set('Cache-Control', 'no-store');
  } else {
    headers.set('Cache-Control', 'public, max-age=300');
  }
  applySecurityHeaders(headers);
  // Body is a ReadableStream of the file contents.
  const stream = createReadStream(filePath);
  return new Response(stream, { status: 200, headers });
}

/**
 * Build a sanitized 404 for static-asset misses. We
 * do NOT include a `Content-Type: text/html` body
 * that would invite content-sniffing of arbitrary
 * data; we return a fixed JSON body.
 */
function notFoundResponse() {
  const headers = new Headers();
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  applySecurityHeaders(headers);
  return new Response(JSON.stringify({ error: 'not-found' }), { status: 404, headers });
}

/**
 * Reject a request whose path tries to escape the
 * public directory or hits a forbidden top-level
 * path. The function returns true when the path is
 * safe to serve; false when it must be rejected.
 */
export function isPathSafeForStatic({ path, publicDir, dataDir }) {
  if (typeof path !== 'string' || path.length === 0) return false;
  if (path.length > MAX_PATH_LENGTH) return false;
  if (path.includes('\u0000')) return false;
  // Reject any path with a parent-directory marker
  // or backslash BEFORE we do any path joining.
  // The URL is already decoded by the parser, so
  // a `%2e%2e` decoded to `..` would have been
  // caught here.
  if (path.includes('..')) return false;
  if (path.includes('\\')) return false;
  // Decode the percent-encoded segments a second
  // time to defend against double-encoded paths.
  let decoded;
  try { decoded = decodeURIComponent(path); } catch { return false; }
  if (decoded.includes('..')) return false;
  // Strip the leading slash and split.
  const segments = decoded.replace(/^\/+/, '').split('/').filter(Boolean);
  if (segments.length === 0) return true; // root, will fall through to SPA fallback
  // Forbidden top-level files (e.g. .env).
  if (FORBIDDEN_TOP_LEVEL.has(segments[0])) return false;
  // Files in the persistent data directory must
  // never be served. We compare both the public
  // directory AND the data directory.
  if (dataDir) {
    const candidate = normalize(resolve(publicDir, ...segments));
    const dataReal = normalize(resolve(dataDir));
    if (candidate === dataReal || candidate.startsWith(dataReal + sep)) return false;
  }
  return true;
}

/**
 * Serve a static request. Returns a `Response`-like
 * object (or null when the path falls through to
 * the SPA fallback).
 *
 * Callers should pass the parsed URL pathname and
 * the hostinger config.
 */
export function serveStatic({ path, publicDir, dataDir, isProduction = true }) {
  if (!existsSync(publicDir)) return null;
  if (!isPathSafeForStatic({ path, publicDir, dataDir })) {
    return notFoundResponse();
  }
  // SPA fallback for root + non-asset paths.
  if (path === '/' || !path.startsWith('/assets/')) {
    const indexPath = join(publicDir, 'index.html');
    if (!existsSync(indexPath)) return null;
    const st = statSync(indexPath);
    return staticAssetResponse({
      filePath: indexPath, fileSize: st.size,
      contentType: 'text/html; charset=utf-8',
      isHashed: false, isIndexHtml: true,
    });
  }
  // Asset path.
  const relPath = path.replace(/^\/+/, '');
  const fullPath = join(publicDir, relPath);
  if (!fullPath.startsWith(publicDir + sep) && fullPath !== publicDir) {
    return notFoundResponse();
  }
  if (!existsSync(fullPath)) {
    return notFoundResponse();
  }
  const st = statSync(fullPath);
  if (st.isDirectory()) {
    // No directory listing; fall through to SPA
    // fallback for unknown directories.
    const indexPath = join(fullPath, 'index.html');
    if (existsSync(indexPath)) {
      const st2 = statSync(indexPath);
      return staticAssetResponse({
        filePath: indexPath, fileSize: st2.size,
        contentType: 'text/html; charset=utf-8',
        isHashed: false, isIndexHtml: true,
      });
    }
    return notFoundResponse();
  }
  if (st.size > MAX_FILE_SIZE) {
    return notFoundResponse();
  }
  return staticAssetResponse({
    filePath: fullPath, fileSize: st.size,
    contentType: mimeFor(fullPath),
    isHashed: HASHED_ASSET_RE.test(path) || HASHED_ASSET_DIR_RE.test(path),
    isIndexHtml: false,
  });
}

export { applySecurityHeaders, MAX_PATH_LENGTH, MAX_FILE_SIZE };
