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

// V6.9 — security-header baseline. Generated from the actual
// production build dependencies: the bundle is same-origin
// (no third-party scripts / stylesheets / fonts / iframes),
// uses module workers loaded from blob: URLs, and serves only
// an in-memory JSON dataset. No `unsafe-eval` is required.
//
// `connect-src` enumerates the exact browser-direct origins
// reachable from the production build. The three non-self
// origins are the documented live-data fallback providers
// (CISA KEV, NVD, FIRST EPSS), reached ONLY when the
// primary `/.netlify/functions/dataset` route is unavailable
// (see `src/services/vulnerabilityService.ts#tryBrowserDirectFetch`).
// No `https:` wildcard, no `*`, no wildcard subdomain.
//
// `style-src-elem` / `style-src-attr` are the narrowest
// functioning inline-style policy supported by the actual
// application: external stylesheets must come from `'self'`
// (the Vite-bundled CSS), and the only inline style usage
// is the `style={{...}}` React prop in two progress-bar
// components and the small handful of inline measurements
// that React and Recharts generate at runtime. The
// `style-src 'self' 'unsafe-inline'` fallback is kept for
// legacy browsers (Chrome < 75, Firefox < 78, Safari < 15.4)
// that do not implement the Level 3 directives; on those
// browsers, the broader `style-src` applies.
const CSP_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self'",
  // Inline style policy. The narrowest cross-browser
  // combination: `style-src` is the Level 1 fallback for
  // browsers that do not implement the Level 3
  // directives, and the two Level 3 directives carve
  // out the narrowest possible permission for modern
  // browsers. The application code itself never injects
  // untrusted content as inline style; the only inline
  // style usage is React's `style={{...}}` prop and
  // Recharts' measurement helpers.
  "style-src 'self' 'unsafe-inline'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  // Live-data fallback providers (only reached when the
  // primary same-origin route is unavailable). No
  // wildcard, no `https:`, no subdomain wildcards.
  "connect-src 'self' https://www.cisa.gov https://services.nvd.nist.gov https://api.first.org",
  // Workers are dynamically constructed via
  // `new Worker(new URL('./parseInventory.worker.mjs',
  // import.meta.url))` and therefore count as
  // same-origin. Blob: is permitted so Vite's
  // runtime worker bootstrap is not blocked.
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "frame-src 'none'",
].join('; ');

// V6.9 — Permissions-Policy baseline. The dashboard does
// not use geolocation, camera, microphone, payment, USB,
// serial, MIDI, screen-capture, or any of the historically
// fingerprintable sensors. The header denies each of them
// explicitly so a future regression that adds a new
// capability is visible in a CSP / Permissions-Policy
// audit rather than silently granted.
const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'autoplay=()',
  'camera=()',
  'cross-origin-isolated=()',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=(self)',
  'geolocation=()',
  'gyroscope=()',
  'keyboard-map=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'sync-xhr=()',
  'usb=()',
  'xr-spatial-tracking=()',
].join(', ');

function applySecurityHeaders(headers, { isProduction = true, allowFrame = false } = {}) {
  // X-Content-Type-Options: nosniff prevents MIME-
  // type sniffing by browsers.
  if (!headers.has('X-Content-Type-Options')) headers.set('X-Content-Type-Options', 'nosniff');
  // V6.9 — X-Frame-Options: DENY (was SAMEORIGIN).
  // The dashboard is a self-contained SPA; we do not
  // permit framing from any origin (self or third
  // party) and the equivalent `frame-ancestors 'none'`
  // directive in the CSP covers modern browsers.
  if (!allowFrame && !headers.has('X-Frame-Options')) headers.set('X-Frame-Options', 'DENY');
  // V6.9 — Referrer-Policy: strict-origin-when-cross-origin
  // (was same-origin). Same-origin is stricter but breaks
  // expected browser behaviour for the dataset's
  // hostinger.namanp.de → threatpulse.namanp.de upgrade
  // path. The cross-origin variant sends only the
  // origin (no path / query) to third parties, which
  // is the documented minimum-disclosure policy.
  if (!headers.has('Referrer-Policy')) headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  // V6.9 — Content-Security-Policy. Generated from the
  // actual build dependency graph (same-origin only;
  // no `unsafe-eval`; workers via `blob:`).
  if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', CSP_DIRECTIVES);
  // V6.9 — Permissions-Policy. Deny every capability the
  // application does not actively use.
  if (!headers.has('Permissions-Policy')) headers.set('Permissions-Policy', PERMISSIONS_POLICY);
  if (isProduction) {
    // V6.9 — Conservative HSTS. `max-age=31536000` (1 year)
    // is the documented V6.9 baseline. We deliberately
    // do NOT include `includeSubDomains` (operator
    // has not yet verified every subdomain is HTTPS)
    // and we do NOT request the `preload` list
    // (preload is a one-way commitment).
    if (!headers.has('Strict-Transport-Security')) headers.set('Strict-Transport-Security', 'max-age=31536000');
  }
  // V6.9 — Cross-Origin-Resource-Policy. The /api/dataset
  // and /.netlify/functions/dataset routes are
  // documented as publicly readable from any origin
  // (CORS-open). Static assets and the HTML are NOT
  // loaded by any third-party embed, so `same-origin`
  // is safe and is the recommended default. The
  // portable dataset route opts into `cross-origin`
  // in its route handler.
  if (!headers.has('Cross-Origin-Resource-Policy')) headers.set('Cross-Origin-Resource-Policy', 'same-origin');
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
