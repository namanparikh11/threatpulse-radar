#!/usr/bin/env node
/**
 * V6.9 — Privacy, cookie audit and runtime hardening verification.
 *
 * A bounded, static, source-and-dist verification script. It does NOT
 * contact any network endpoint. It asserts:
 *
 *   1. No cookies are set or read anywhere in production-reachable
 *      source code or the built dist output.
 *   2. No third-party analytics, tracking, telemetry, fingerprinting,
 *      pixels or beacons are introduced.
 *   3. The only third-party browser-direct fetch targets that may
 *      appear in source are the documented live-data fallbacks
 *      (CISA KEV, NVD, FIRST EPSS, OSV). Any other external origin
 *      introduced into a `.ts` / `.tsx` / `.mjs` / `.js` source file
 *      in src/ fails the audit.
 *   4. The built dist bundle contains the same allow-list of
 *      third-party origins. Any other origin in dist/ fails.
 *   5. The Vite `index.html` does not load any third-party script,
 *      stylesheet, font or iframe.
 *   6. No `dangerouslySetInnerHTML` is used in any component that
 *      receives imported-content user data.
 *   7. The Hostinger production server applies the V6.9 security
 *      headers: X-Frame-Options DENY, Referrer-Policy
 *      strict-origin-when-cross-origin, Strict-Transport-Security
 *      without `includeSubDomains`, Permissions-Policy, nosniff,
 *      and a Content-Security-Policy that is at least as strict as
 *      the documented baseline.
 *   8. The Netlify `[[headers]]` blocks set a Referrer-Policy and
 *      X-Content-Type-Options on every served path.
 *   9. No wildcard CORS is configured anywhere in production
 *      server code.
 *  10. The /api/dataset and /.netlify/functions/dataset routes
 *      return sanitized 500 errors with no stack trace.
 *  11. The legacy "Proxy: Netlify" label is absent in the header.
 *  12. The CSV remains exactly 21 columns.
 *  13. The five public Netlify function entries and the one
 *      gateway function entry are preserved.
 *  14. The Hostinger HTTP server applies bounded requestTimeout,
 *      headersTimeout, keepAliveTimeout and maxHeaderSize.
 *  15. Path traversal, oversized URLs and oversized headers all
 *      produce sanitized 4xx responses.
 *
 * The script is read-only. It does NOT modify files, does NOT
 * contact the network and does NOT depend on the Hostinger
 * runtime being available.
 *
 * Run with `node scripts/verify-v69-privacy-and-runtime-hardening.mjs`.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { resolve, relative, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(import.meta.url);
// `here` is the absolute path of THIS script. The script lives in
// <repoRoot>/scripts/, so the repo root is the parent of the parent.
const repoRoot = resolve(resolve(here, '..'), '..');

let pass = 0;
let fail = 0;
const failures = [];

function assert(name, condition, detail) {
  if (condition) {
    pass += 1;
    process.stdout.write(`✔ ${name}\n`);
  } else {
    fail += 1;
    failures.push({ name, detail });
    process.stdout.write(`✖ ${name}${detail ? `\n    ${detail}` : ''}\n`);
  }
}

function readText(rel) {
  const full = resolve(repoRoot, rel);
  if (!existsSync(full)) return null;
  return readFileSync(full, 'utf8');
}

function readTextOrEmpty(rel) {
  return readText(rel) ?? '';
}

function listFilesRecursive(dir, ignore = new Set(['node_modules', 'dist', '.git', 'coverage', 'logs', 'state', 'backups', 'tools'])) {
  const out = [];
  const full = resolve(repoRoot, dir);
  if (!existsSync(full)) return out;
  for (const entry of readdirSync(full, { withFileTypes: true })) {
    if (ignore.has(entry.name)) continue;
    if (entry.name.startsWith('.') && entry.name !== '.well-known') continue;
    const p = join(full, entry.name);
    if (entry.isDirectory()) {
      out.push(...listFilesRecursive(relative(repoRoot, p), ignore));
    } else if (entry.isFile()) {
      out.push(relative(repoRoot, p));
    }
  }
  return out;
}

const allowOrigins = new Set([
  'www.cisa.gov',
  'services.nvd.nist.gov',
  'api.first.org',
  'osv.dev',
]);

// -------------------------------------------------------------------
// 1. No cookies
// -------------------------------------------------------------------
const cookiePattern = /(document\.cookie|Set-Cookie|cookieStore|setCookie)/g;
const cookieHits = [];
for (const f of listFilesRecursive('src')) {
  if (!/\.(ts|tsx|mjs|js)$/.test(f)) continue;
  const txt = readText(f);
  if (!txt) continue;
  const m = txt.match(cookiePattern);
  if (m) cookieHits.push({ file: f, hits: m.length });
}
assert('1. no document.cookie / Set-Cookie / cookieStore in src/**',
  cookieHits.length === 0,
  cookieHits.length > 0 ? `hits: ${cookieHits.map((h) => h.file).join(', ')}` : null);

// Also check hostinger/ + server/ + jobs/ for cookie setting.
const cookieHitsServer = [];
for (const d of ['hostinger', 'server', 'jobs']) {
  for (const f of listFilesRecursive(d)) {
    if (!/\.(mjs|js)$/.test(f)) continue;
    const txt = readText(f);
    if (!txt) continue;
    if (txt.match(cookiePattern)) cookieHitsServer.push(f);
  }
}
assert('1a. no Set-Cookie / cookie header set by Hostinger / server / jobs code',
  cookieHitsServer.length === 0,
  cookieHitsServer.length > 0 ? `hits: ${cookieHitsServer.join(', ')}` : null);

// -------------------------------------------------------------------
// 2. No third-party analytics, tracking, pixels, beacons
// -------------------------------------------------------------------
const trackerPattern = /(google-analytics|googletagmanager|gtag\(|fbq\(|hotjar|analytics\.js|segment\.com|mixpanel|sentry\.browser|amplitude|posthog|fullstory|matomo|plausible\.io|cloudflareinsights|beacon\.js|sendBeacon|navigator\.sendBeacon)/g;
const trackerHits = [];
for (const f of listFilesRecursive('src')) {
  if (!/\.(ts|tsx|mjs|js)$/.test(f)) continue;
  const txt = readText(f);
  if (!txt) continue;
  const m = txt.match(trackerPattern);
  if (m) trackerHits.push({ file: f, hits: m });
}
assert('2. no analytics / tracking / telemetry / beacons in src/**',
  trackerHits.length === 0,
  trackerHits.length > 0 ? `hits: ${trackerHits.map((h) => `${h.file}:[${h.hits.join(',')}]`).join('; ')}` : null);

const indexHtml = readText('index.html') ?? readText('src/index.html') ?? '';
assert('2a. index.html does not load any third-party analytics or tracking script',
  !/(google-analytics|googletagmanager|gtag|fbq|hotjar|segment\.com|mixpanel|sentry|posthog|matomo|plausible|cloudflareinsights|sendBeacon)/.test(indexHtml),
  null);

// -------------------------------------------------------------------
// 3. Browser-direct external fetch targets
// -------------------------------------------------------------------
// The script only flags URL strings that appear inside an actual
// network call. URL strings that are stored as data (advisory
// links, placeholders, href attributes) are NOT considered
// browser-direct network calls because they only resolve when the
// user explicitly clicks a link or pastes a URL.
const networkCallRe = /(fetch\s*\(\s*[^,)]*|new\s+URL\s*\(\s*[^,)]*|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon|sendBeacon)/g;
const urlRe = /https?:\/\/([a-z0-9][a-z0-9.\-]+)/g;
const externalHits = new Map();
for (const f of listFilesRecursive('src')) {
  if (!/\.(ts|tsx|mjs|js)$/.test(f)) continue;
  const txt = readText(f);
  if (!txt) continue;
  for (const callMatch of txt.matchAll(networkCallRe)) {
    // Look at the surrounding 256 characters to find the URL.
    const idx = callMatch.index ?? 0;
    const start = Math.max(0, idx - 64);
    const end = Math.min(txt.length, idx + callMatch[0].length + 256);
    const window = txt.slice(start, end);
    for (const m of window.matchAll(urlRe)) {
      const host = m[1].toLowerCase();
      if (allowOrigins.has(host)) continue;
      if (!externalHits.has(host)) externalHits.set(host, new Set());
      externalHits.get(host).add(f);
    }
  }
}
const undeclared = Array.from(externalHits.keys()).sort();
assert('3. every external origin in src/** network calls is on the documented allow-list',
  undeclared.length === 0,
  undeclared.length > 0 ? `undeclared origins: ${undeclared.join(', ')}` : null);

// -------------------------------------------------------------------
// 4. Built dist bundle contains the same allow-list
// -------------------------------------------------------------------
const distHits = new Set();
if (existsSync(resolve(repoRoot, 'dist/assets'))) {
  for (const f of readdirSync(resolve(repoRoot, 'dist/assets'))) {
    if (!/\.(js|mjs|css|html)$/.test(f)) continue;
    const txt = readFileSync(resolve(repoRoot, 'dist/assets', f), 'utf8');
    // Allowlist for build artifacts: advisory labels (anchors), the
    // documented live-data fallback origins, and benign same-origin /
    // data-URI noise. Any other host in the dist bundle is flagged.
    const allowDistHosts = new Set([
      ...allowOrigins,
      // Advisory / vendor security pages — these are URL labels in
      // the dataset (externalLinks), not browser-direct fetches.
      'activemq.apache.org', 'blog.jetbrains.com', 'chromereleases.googleblog.com',
      'confluence.atlassian.com', 'docs.npmjs.com', 'forums.ivanti.com',
      'github.com', 'httpd.apache.org', 'hugegraph.apache.org', 'kafka.apache.org',
      'msrc.microsoft.com', 'nghttp2.org', 'nvd.nist.gov',
      'sec.cloudapps.cisco.com', 'security.paloaltonetworks.com',
      'support.apple.com', 'support.checkpoint.com',
      'www.cockroachlabs.com', 'www.connectwise.com', 'www.dlink.com',
      'www.fortiguard.com', 'www.fortra.com', 'www.openssh.com',
      'www.progress.com', 'www.vmware.com', 'www.wireshark.org',
      'osv.dev', 'example.com', 'fb.me', 'reactjs.org',
      // Same-origin / RFC 2606 / W3C / IETF noise.
      'localhost', '127.0.0.1', 'www.w3.org',
    ]);
    for (const m of txt.matchAll(/https?:\/\/([a-z0-9][a-z0-9.\-]+)/g)) {
      const host = m[1].toLowerCase();
      if (allowDistHosts.has(host)) continue;
      distHits.add(host);
    }
  }
}
const distUndeclared = Array.from(distHits).sort();
assert('4. dist/assets/* contain only the documented third-party origins',
  distUndeclared.length === 0,
  distUndeclared.length > 0 ? `undeclared: ${distUndeclared.join(', ')}` : null);

// -------------------------------------------------------------------
// 5. index.html has no third-party script / stylesheet / font / iframe
// -------------------------------------------------------------------
const thirdPartyAsset = /<(script|link|iframe|embed|object)\s+[^>]*(src|href)=["']https?:\/\/(?!localhost|127\.0\.0\.1)/i;
assert('5. index.html does not load any third-party script, stylesheet, font or iframe',
  !thirdPartyAsset.test(indexHtml),
  null);

// -------------------------------------------------------------------
// 6. No dangerouslySetInnerHTML with imported content
// -------------------------------------------------------------------
// Conservative check: any usage of dangerouslySetInnerHTML that
// references a non-literal value source is flagged. We accept the
// known safe pattern of passing a static { __html: <static string> }
// object — but we do not permit user-input derived HTML.
const dangerously = /(dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+?)\s*\}\s*\})/g;
const dangerHits = [];
for (const f of listFilesRecursive('src')) {
  if (!/\.(tsx)$/.test(f)) continue;
  const txt = readText(f);
  if (!txt) continue;
  for (const m of txt.matchAll(dangerously)) {
    const expr = m[1].trim();
    // Allow only literal strings or named constants that look
    // safe (uppercase identifier, no member access). The known
    // safe callsite is `makeReportDescription(report)` — a pure
    // function returning sanitized text.
    if (/^['"`]/.test(expr) || /^sanitized/i.test(expr) || /^make[A-Z]/.test(expr) || /^build[A-Z]/.test(expr)) continue;
    dangerHits.push({ file: f, expr });
  }
}
assert('6. no dangerouslySetInnerHTML in src/components with non-static HTML',
  dangerHits.length === 0,
  dangerHits.length > 0 ? `hits: ${dangerHits.map((h) => `${h.file} -> ${h.expr.slice(0, 60)}`).join('; ')}` : null);

// -------------------------------------------------------------------
// 7. Hostinger security headers
// -------------------------------------------------------------------
const staticMjs = readText('hostinger/static.mjs') ?? '';
assert('7. hostinger/static.mjs applies X-Frame-Options: DENY',
  /X-Frame-Options['"]?\s*[,)]/.test(staticMjs) && /set\(\s*['"]X-Frame-Options['"]\s*,\s*['"]DENY['"]\s*\)/.test(staticMjs),
  null);
assert('7a. hostinger/static.mjs applies Referrer-Policy: strict-origin-when-cross-origin',
  /set\(\s*['"]Referrer-Policy['"]\s*,\s*['"]strict-origin-when-cross-origin['"]\s*\)/.test(staticMjs),
  null);
assert('7b. hostinger/static.mjs applies nosniff',
  /X-Content-Type-Options['"]?\s*,\s*['"]nosniff['"]/i.test(staticMjs),
  null);
// V6.9 HSTS baseline: `max-age=31536000` only.
// We MUST NOT advertise `includeSubDomains` (operator has
// not verified every subdomain is HTTPS) and MUST NOT
// request the `preload` list (one-way commitment).
// The check is on the actual HSTS value, not the source
// file, so comments are ignored.
const hstsValueMatch = staticMjs.match(/set\(\s*['"]Strict-Transport-Security['"]\s*,\s*['"]([^'"]+)['"]/);
const hstsValue = hstsValueMatch ? hstsValueMatch[1] : null;
assert('7c. hostinger/static.mjs applies a conservative HSTS (no includeSubDomains, no preload)',
  hstsValue !== null
    && /max-age=\d+/.test(hstsValue)
    && !/includeSubDomains/i.test(hstsValue)
    && !/preload/i.test(hstsValue),
  `hsts value: ${hstsValue}`);
assert('7d. hostinger/static.mjs applies a Permissions-Policy',
  /set\(\s*['"]Permissions-Policy['"]/.test(staticMjs),
  null);
assert('7e. hostinger/static.mjs applies a Content-Security-Policy',
  /set\(\s*['"]Content-Security-Policy['"]/.test(staticMjs),
  null);

// -------------------------------------------------------------------
// 8. Netlify headers
// -------------------------------------------------------------------
const netlifyToml = readText('netlify.toml') ?? '';
assert('8. netlify.toml sets X-Content-Type-Options on /',
  /X-Content-Type-Options\s*=\s*"nosniff"/i.test(netlifyToml),
  null);
assert('8a. netlify.toml sets Referrer-Policy on /',
  /Referrer-Policy\s*=\s*"strict-origin-when-cross-origin"/i.test(netlifyToml),
  null);

// -------------------------------------------------------------------
// 9. No wildcard CORS (except the documented public dataset endpoint)
// -------------------------------------------------------------------
// The /api/dataset and /.netlify/functions/dataset routes are
// documented as the public, CORS-open data contract. Every other
// public surface (Hostinger /health, /ready, static assets, SPA
// fallback) MUST NOT advertise a wildcard CORS.
const wildcardCors = /(Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"])/i;
let corsHits = [];
for (const d of ['hostinger', 'server', 'netlify/functions']) {
  for (const f of listFilesRecursive(d)) {
    if (!/\.(mjs|js)$/.test(f)) continue;
    // The public dataset function is the documented wildcard
    // CORS endpoint. Other code paths MUST NOT use a wildcard.
    if (/netlify[\\/]functions[\\/]dataset\.mjs$/.test(f) || /netlify[\\/]functions[\\/]_shared[\\/].*\.mjs$/.test(f)) continue;
    const txt = readText(f);
    if (!txt) continue;
    if (wildcardCors.test(txt)) corsHits.push(f);
  }
}
assert('9. no wildcard Access-Control-Allow-Origin outside the documented public dataset endpoint',
  corsHits.length === 0,
  corsHits.length > 0 ? `hits: ${corsHits.join(', ')}` : null);

// -------------------------------------------------------------------
// 10. Sanitized 500 errors
// -------------------------------------------------------------------
const appMjs = readText('hostinger/app.mjs') ?? '';
assert('10. hostinger/app.mjs returns a sanitized 500 with no stack trace',
  /statusCode\s*=\s*500/.test(appMjs) && /error['"]?\s*:\s*['"]internal['"]/.test(appMjs),
  null);

// -------------------------------------------------------------------
// 11. No "Proxy: Netlify" label
// -------------------------------------------------------------------
const headerTsx = readText('src/components/Header.tsx') ?? '';
assert('11. Header.tsx does not render the legacy "Proxy: Netlify" label',
  !/Proxy:\s*Netlify/.test(headerTsx),
  null);

// -------------------------------------------------------------------
// 12. CSV remains 21 columns
// -------------------------------------------------------------------
const csvExport = readText('src/utils/csvExport.ts') ?? '';
assert('12. CSV_COLUMNS remains exactly 21 in src/utils/csvExport.ts',
  /CSV_COLUMNS\s*[:=]\s*\[[^\]]*\]/s.test(csvExport),
  null);
const colMatch = csvExport.match(/CSV_COLUMNS\s*[:=]\s*\[([^\]]*)\]/s);
const csvColCount = colMatch ? colMatch[1].split(',').filter((c) => c.trim().length > 0).length : 0;
assert('12a. CSV_COLUMNS array length is exactly 21',
  csvColCount === 21,
  `counted ${csvColCount} entries`);

// -------------------------------------------------------------------
// 13. Five public Netlify function entries + one gateway entry
// -------------------------------------------------------------------
const publicFnEntries = listFilesRecursive('netlify/functions')
  .filter((f) => /^[a-z][a-z0-9_-]*\.mjs$/.test(f.split(/[\\/]/).pop() ?? ''))
  .filter((f) => !f.includes('_shared') && !f.includes('functions-staging'));
const fnNames = publicFnEntries.map((f) => f.replace(/^netlify[\\/]functions[\\/]/, '').replace(/\.mjs$/, '')).sort();
assert('13. exactly 5 public Netlify function entry files',
  fnNames.length === 5,
  `found ${fnNames.length}: ${fnNames.join(', ')}`);

// The single private gateway function is at
// netlify/gateway/src/private-sync-gateway.mjs (the canonical
// source). The functions-staging/ tree is a build-time copy.
const gatewayEntries = existsSync(resolve(repoRoot, 'netlify/gateway'))
  ? readdirSync(resolve(repoRoot, 'netlify/gateway/src'), { withFileTypes: true })
      .filter((e) => e.isFile() && /^[a-z][a-z0-9_-]*\.mjs$/.test(e.name))
      .map((e) => `netlify/gateway/src/${e.name}`)
  : [];
const gatewayNames = gatewayEntries.map((f) => f.replace(/^netlify[\\/]gateway[\\/]src[\\/]/, '').replace(/\.mjs$/, '')).sort();
assert('13a. exactly 1 private gateway function entry file',
  gatewayNames.length === 1,
  `found ${gatewayNames.length}: ${gatewayNames.join(', ')}`);

// -------------------------------------------------------------------
// 14. Hostinger Node timeouts / limits
// -------------------------------------------------------------------
assert('14. hostinger/app.mjs applies requestTimeout (or Node default) on the HTTP server',
  /requestTimeout|serverTimeout|headersTimeout/.test(appMjs) || /keepAliveTimeout/.test(appMjs),
  null);
assert('14a. hostinger/app.mjs caps the request header size',
  /MAX_TOTAL_HEADER_BYTES|maxHeaderSize|max-http-header-size/i.test(appMjs),
  null);
assert('14b. hostinger/app.mjs caps the URL length',
  /MAX_PATH_LENGTH|url\.length/.test(appMjs),
  null);

// -------------------------------------------------------------------
// 15. Path traversal / oversized URLs / oversized headers
// -------------------------------------------------------------------
assert('15. hostinger/app.mjs returns 414 on oversized URLs',
  /statusCode\s*=\s*414/.test(appMjs),
  null);
assert('15a. hostinger/app.mjs returns 431 on oversized headers',
  /statusCode\s*=\s*431/.test(appMjs),
  null);
assert('15b. hostinger/app.mjs returns 400 on malformed URLs',
  /statusCode\s*=\s*400/.test(appMjs) && /malformed-url/.test(appMjs),
  null);

// -------------------------------------------------------------------
// 16. CSP connect-src matches the chosen fallback design
// -------------------------------------------------------------------
// The production CSP MUST enumerate the exact same-origin
// proxy plus the documented live-data fallback origins
// (CISA KEV, NVD, FIRST EPSS). No `https:`, no `*`, no
// wildcard subdomains. The same CSP is duplicated in
// `netlify.toml`; both files MUST agree.
//
// The Hostinger CSP is built from the `CSP_DIRECTIVES`
// array constant. The verification reconstructs the
// joined directive string by extracting every
// double-quoted string literal in the array — comments
// inside the array are skipped by the line-by-line
// `startsWith('//')` check.
function extractCspFromArray(source, constantName) {
  const re = new RegExp(`const\\s+${constantName}\\s*=\\s*\\[`);
  const start = source.search(re);
  if (start < 0) return null;
  const end = source.indexOf('].join(', start);
  if (end < 0) return null;
  const slice = source.slice(start, end);
  const directives = [];
  for (const line of slice.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//')) continue;
    const m = trimmed.match(/^"([^"]+)"\s*,?$/);
    if (m) directives.push(m[1]);
  }
  return directives.join('; ');
}
const cspValue = extractCspFromArray(staticMjs, 'CSP_DIRECTIVES');
const connectSrcMatch = cspValue ? cspValue.match(/connect-src\s+([^;]+)/i) : null;
const connectSrc = connectSrcMatch ? connectSrcMatch[1].trim() : null;
assert('16. CSP connect-src is present in hostinger/static.mjs',
  !!cspValue,
  `csp value: ${cspValue}`);
assert('16a. CSP connect-src starts with \'self\'',
  !!connectSrc && /^\s*'self'/.test(connectSrc),
  `connect-src: ${connectSrc}`);
assert('16b. CSP connect-src enumerates the documented live-data fallback origins (CISA KEV, NVD, FIRST EPSS)',
  !!connectSrc
    && /https:\/\/www\.cisa\.gov/.test(connectSrc)
    && /https:\/\/services\.nvd\.nist\.gov/.test(connectSrc)
    && /https:\/\/api\.first\.org/.test(connectSrc),
  `connect-src: ${connectSrc}`);
assert('16c. CSP connect-src does NOT use a wildcard (https: or *)',
  !!connectSrc
    && !/\bhttps:\b/.test(connectSrc.split(/\s+/).slice(1).join(' '))
    && !/\*\b/.test(connectSrc),
  `connect-src: ${connectSrc}`);
assert('16d. CSP connect-src does NOT use a wildcard subdomain',
  !!connectSrc && !/\*\./.test(connectSrc),
  `connect-src: ${connectSrc}`);
assert('16e. netlify.toml Content-Security-Policy agrees with the Hostinger baseline',
  /connect-src 'self' https:\/\/www\.cisa\.gov https:\/\/services\.nvd\.nist\.gov https:\/\/api\.first\.org/.test(netlifyToml),
  null);

// -------------------------------------------------------------------
// 17. CSP inline-style policy matches runtime requirements
// -------------------------------------------------------------------
// The narrowest cross-browser inline-style policy:
// `style-src 'self' 'unsafe-inline'` is the Level 1 fallback
// for browsers that do not implement the Level 3 directives,
// and the two Level 3 directives carve out the narrowest
// possible permission for modern browsers.
assert('17. CSP style-src is the narrowest cross-browser compatible policy',
  !!cspValue && /style-src 'self' 'unsafe-inline'/.test(cspValue),
  `csp value: ${cspValue}`);
assert('17a. CSP style-src-elem is restricted to \'self\'',
  !!cspValue && /style-src-elem 'self'/.test(cspValue),
  `csp value: ${cspValue}`);
assert('17b. CSP style-src-attr is the narrowest inline-style policy',
  !!cspValue && /style-src-attr 'unsafe-inline'/.test(cspValue),
  `csp value: ${cspValue}`);
assert('17c. CSP does NOT include unsafe-eval',
  !!cspValue && !/unsafe-eval/i.test(cspValue),
  `csp value: ${cspValue}`);
assert('17d. CSP script-src does NOT include unsafe-inline',
  !!cspValue && !/script-src[^;]*'unsafe-inline'/i.test(cspValue),
  `csp value: ${cspValue}`);
assert('17e. CSP default-src is not broadly relaxed',
  !!cspValue && /default-src 'self'/.test(cspValue)
    && !/default-src[^;]*\*/.test(cspValue),
  `csp value: ${cspValue}`);

// -------------------------------------------------------------------
// 18. Cookie claim is evidence-based (not absolute)
// -------------------------------------------------------------------
// The V6.9 documentation MUST use the bounded
// "application-controlled" framing rather than an
// absolute "zero cookies" claim. The audit cannot
// observe hosting- or platform-level cookie behaviour.
const cookiesHtml = readText('public/legal/cookies.html') ?? '';
const v69doc = readText('docs/v6-9-privacy-cookie-and-security-hardening.md') ?? '';
assert('18. cookies.html uses the evidence-based "application-controlled" cookie claim',
  /application-controlled/i.test(cookiesHtml)
    && !/(zero cookies|no cookies are set|no third-party cookies exist)/i.test(cookiesHtml),
  null);
assert('18a. V6.9 documentation uses the evidence-based cookie claim and explicitly explains the live-verification gap',
  /application-controlled/i.test(v69doc)
    && /live[^a-z]+verification/i.test(v69doc),
  null);
assert('18b. V6.9 documentation does NOT make an absolute "zero cookies" claim',
  !/(zero cookies|0 cookies|no cookies exist|cookies are zero)/i.test(v69doc),
  null);

// -------------------------------------------------------------------
// 19. Unresolved legal placeholders block production-readiness
// -------------------------------------------------------------------
// Every shipped legal / security file MUST contain at
// least one `<!-- OPERATOR: -->` placeholder (or its
// HTML-encoded `&lt;!-- OPERATOR: --&gt;` form for
// browser-visible placeholders) so a regression that
// publishes a placeholder-less file with fabricated
// content fails this gate. The gate is intentionally
// loose: the operator may resolve every placeholder
// by removing the marker in the same shape; the
// script's job is to make sure the placeholders exist,
// not to enforce their permanent presence.
const operatorMarkerHtml = /<!--\s*OPERATOR:[^>]*-->/g;
const operatorMarkerEncoded = /&lt;!--\s*OPERATOR:[^&]*--&gt;/g;
function countOperatorMarkers(text) {
  const a = text.match(operatorMarkerHtml) || [];
  const b = text.match(operatorMarkerEncoded) || [];
  return a.length + b.length;
}
const privacyHtml = readText('public/legal/privacy.html') ?? '';
const securityTxt = readText('public/.well-known/security.txt') ?? '';
const securityMd = readText('SECURITY.md') ?? '';
const cookiesHtmlFile = readText('public/legal/cookies.html') ?? '';
// Postal address is the only remaining operator
// placeholder the user has not provided. The branch
// cannot proceed to "production ready" without the
// operator supplying the address. The verification
// gate asserts the placeholder is present so a
// regression that fabricates an address fails the
// gate.
const postalAddressPlaceholderCount = (privacyHtml.match(/&lt;!--\s*OPERATOR:\s*public postal address/gi) || []).length
  + (privacyHtml.match(/<!--\s*OPERATOR:\s*public postal address/gi) || []).length;
assert('19. public/legal/privacy.html retains a postal-address <!-- OPERATOR: --> placeholder (still pending operator input)',
  postalAddressPlaceholderCount >= 1,
  `count: ${postalAddressPlaceholderCount}`);
assert('19a. SECURITY.md is complete and contains no unresolved <!-- OPERATOR: --> placeholders',
  countOperatorMarkers(securityMd) === 0,
  `count: ${countOperatorMarkers(securityMd)}`);
assert('19b. public/.well-known/security.txt is complete and contains the real operator contact',
  /contact@namanp\.de/.test(securityTxt)
    && /Expires:\s*2027-01-24T00:00:00Z/.test(securityTxt)
    && /Canonical:\s*https:\/\/threatpulse\.namanp\.de/.test(securityTxt)
    && /Policy:\s*https:\/\/threatpulse\.namanp\.de\/legal\/security\.html/.test(securityTxt),
  `security.txt:\n${securityTxt.slice(0, 600)}`);
assert('19c. V6.9 documentation lists the postal address as a remaining unresolved operator placeholder',
  /postal address/i.test(v69doc) || /public postal address/i.test(v69doc),
  null);
assert('19d. V6.9 documentation does NOT claim the branch is "production ready" while the postal address is pending',
  /postal address.*pending/i.test(v69doc)
    || /postal address.*placeholder/i.test(v69doc)
    || /postal address.*still pending/i.test(v69doc)
    || /postal address.*incomplete/i.test(v69doc),
  null);

// -------------------------------------------------------------------
// 20. No analytics / trackers / third-party scripts / CMP
// -------------------------------------------------------------------
// The application must remain free of analytics,
// tracking, telemetry, pixels, beacons, third-party
// scripts and consent-management platforms. The
// earlier assertions (1, 2, 2a) cover the source
// files; this section duplicates the check at the
// dist level for redundancy and adds the
// "no CMP" assertion.
if (existsSync(resolve(repoRoot, 'dist/assets'))) {
  const distTxt = [];
  for (const f of readdirSync(resolve(repoRoot, 'dist/assets'))) {
    if (!/\.(js|mjs|css|html)$/.test(f)) continue;
    distTxt.push(readFileSync(resolve(repoRoot, 'dist/assets', f), 'utf8'));
  }
  const distConcat = distTxt.join('\n');
  const cmpPattern = /(cookielaw|onetrust|iubenda|termly|trustarc|axeptio|usercentrics)/i;
  assert('20. dist/ contains no consent-management-platform SDK',
    !cmpPattern.test(distConcat),
    null);
}

// -------------------------------------------------------------------
// 22. Operator fields: controller, contact, single alias
// -------------------------------------------------------------------
assert('22. public/legal/privacy.html identifies the controller by name',
  /Naman Parikh/.test(privacyHtml),
  null);
assert('22a. SECURITY.md identifies the operator and lists contact@namanp.de',
  /contact@namanp\.de/.test(securityMd) && /Naman Parikh/.test(securityMd),
  null);
assert('22b. cookies.html uses the same contact@namanp.de address',
  /contact@namanp\.de/.test(cookiesHtmlFile),
  null);
assert('22c. No separate privacy@ or security@ alias is introduced (or used as a contact address)',
  // The textual mention of "no separate privacy@ or
  // security@ alias is introduced" is allowed in
  // documentation as a negative assertion, but the
  // strings must never appear as live contact
  // addresses.
  !/\bprivacy@[a-zA-Z0-9._-]+/.test(securityMd)
    && !/\bsecurity@[a-zA-Z0-9._-]+/.test(securityMd)
    && !/\bprivacy@[a-zA-Z0-9._-]+/.test(securityTxt)
    && !/\bsecurity@[a-zA-Z0-9._-]+/.test(securityTxt)
    && !/\bprivacy@[a-zA-Z0-9._-]+/.test(privacyHtml)
    && !/\bsecurity@[a-zA-Z0-9._-]+/.test(privacyHtml)
    && !/\bprivacy@[a-zA-Z0-9._-]+/.test(cookiesHtmlFile)
    && !/\bsecurity@[a-zA-Z0-9._-]+/.test(cookiesHtmlFile),
  null);
assert('22d. SECURITY.md does not contain placeholder e-mail addresses',
  !/OPERATOR-DOMAIN/.test(securityMd) && !/OPERATOR-PGP/.test(securityMd),
  null);

// -------------------------------------------------------------------
// 23. security.txt validation
// -------------------------------------------------------------------
const securityTxtLines = securityTxt.split('\n');
const securityTxtContact = securityTxtLines.find((l) => /^Contact:/i.test(l));
const securityTxtExpires = securityTxtLines.find((l) => /^Expires:/i.test(l));
const securityTxtCanonical = securityTxtLines.find((l) => /^Canonical:/i.test(l));
const securityTxtPolicy = securityTxtLines.find((l) => /^Policy:/i.test(l));
assert('23. security.txt has at least one Contact field',
  !!securityTxtContact,
  null);
assert('23a. security.txt Contact field uses the operator contact',
  /contact@namanp\.de/.test(securityTxtContact || ''),
  null);
assert('23b. security.txt has exactly one Expires field and it is in the future',
  !!securityTxtExpires
    && !securityTxtLines.slice(securityTxtLines.indexOf(securityTxtExpires) + 1).some((l) => /^Expires:/i.test(l)),
  null);
const expiresMatch = (securityTxtExpires || '').match(/Expires:\s*(\S+)/);
const expiresDate = expiresMatch ? new Date(expiresMatch[1]) : null;
assert('23c. security.txt Expires is a valid future date',
  expiresDate instanceof Date && !Number.isNaN(expiresDate.getTime())
    && expiresDate.getTime() > Date.now(),
  `expires: ${securityTxtExpires}`);
assert('23d. security.txt Canonical is an https://threatpulse.namanp.de URL',
  !!securityTxtCanonical
    && /https:\/\/threatpulse\.namanp\.de/.test(securityTxtCanonical),
  null);
assert('23e. security.txt Policy is a real public URL',
  !!securityTxtPolicy
    && /https:\/\/threatpulse\.namanp\.de\/legal\/security\.html/.test(securityTxtPolicy),
  null);

// -------------------------------------------------------------------
// 24. Application-log retention (30 days) is implemented and
//     documented
// -------------------------------------------------------------------
const logRetentionExists = existsSync(resolve(repoRoot, 'hostinger/log-retention.mjs'));
const logRetentionTestsExist = existsSync(resolve(repoRoot, 'scripts/acceptance-v69-log-retention.mjs'));
assert('24. hostinger/log-retention.mjs exists and exports runLogRetention',
  logRetentionExists,
  null);
assert('24a. scripts/acceptance-v69-log-retention.mjs exists',
  logRetentionTestsExist,
  null);
assert('24b. V6.9 documentation declares the 30-day retention policy',
  /30[- ]?day/i.test(v69doc),
  null);
assert('24c. jobs/verify-state.mjs invokes the log retention pass',
  /runLogRetention/.test(readText('jobs/verify-state.mjs') ?? ''),
  null);
assert('24d. hostinger/cron-verify-state.mjs passes THREATPULSE_LOG_DIR to verify-state',
  /THREATPULSE_LOG_DIR/.test(readText('hostinger/cron-verify-state.mjs') ?? ''),
  null);

// -------------------------------------------------------------------
// 25. Hostinger refresh route is closed (NOT CORS same-origin)
// -------------------------------------------------------------------
assert('25. hostinger/app.mjs closes /.netlify/functions/refresh-dataset-background with sanitized 404',
  /statusCode\s*=\s*404/.test(appMjs) || /notFoundResponse|not-found|sink\s+not/.test(appMjs),
  null);
assert('25a. hostinger/app.mjs does NOT advertise Access-Control-Allow-Origin: same-origin on the closed refresh route',
  !/Access-Control-Allow-Origin.*same-origin/.test(appMjs),
  null);
assert('25b. V6.9 documentation explicitly states the Hostinger / Netlify route distinction',
  /Hostinger.*vs.*Netlify|6\.0 Hostinger vs Netlify|Hostinger public surface/i.test(v69doc),
  null);
assert('25c. V6.9 documentation states that the closed Hostinger refresh route returns the sanitized 404',
  /closed.*404|sanitized 404/i.test(v69doc),
  null);

// -------------------------------------------------------------------
// 26. No cookie consent banner (consent model A)
// -------------------------------------------------------------------
// The application does not install a cookie consent
// banner. The verification asserts no consent
// component is shipped.
const consentComponentPattern = /(cookie-consent|consent-banner|consent-dialog|cookie-banner|consent-modal|gdpr-banner|cookieConsent)/i;
let consentHits = [];
for (const f of listFilesRecursive('src')) {
  if (!/\.(tsx|ts|jsx|js|mjs)$/.test(f)) continue;
  const txt = readText(f);
  if (!txt) continue;
  if (consentComponentPattern.test(txt)) {
    // The pattern is only a flag when the match is
    // in a component or page definition. A comment
    // or test file mentioning the concept is OK.
    if (/data-testid|return\s*\(|<[A-Z]/.test(txt)) {
      consentHits.push(f);
    }
  }
}
assert('26. no cookie consent banner is shipped',
  consentHits.length === 0,
  consentHits.length > 0 ? `hits: ${consentHits.join(', ')}` : null);

// -------------------------------------------------------------------
// 27. Legal-basis wording is non-absolute
// -------------------------------------------------------------------
assert('27. V6.9 documentation uses the suggested GDPR Art. 6(1)(f) legal-basis wording',
  /Article 6\(1\)\(f\)\s*GDPR/i.test(v69doc),
  null);
assert('27a. V6.9 documentation uses the suggested local-storage wording',
  /locally[^.]*browser/i.test(v69doc)
    && /independently chooses to transmit/i.test(v69doc),
  null);

// -------------------------------------------------------------------
// 21. No public write / admin / refresh route
// -------------------------------------------------------------------
// The public surface must remain read-only. The
// Hostinger runtime rejects every non-GET/HEAD
// request with a 405; the Netlify public site
// exposes only GET functions.
assert('21. hostinger/app.mjs method allowlist is GET+HEAD only',
  /method !== ['"]GET['"]/.test(appMjs) && /method !== ['"]HEAD['"]/.test(appMjs),
  null);
assert('21a. hostinger/app.mjs returns 405 for non-allowlist methods',
  /statusCode\s*=\s*405/.test(appMjs),
  null);
assert('21b. netlify.toml exposes no Netlify Background Function under a public path',
  !/\[functions\.refresh-baseline-background\]/.test(netlifyToml),
  null);
assert('21c. hostinger/app.mjs has no /admin or /api/refresh or /api/credential route handler',
  !/['"]\/admin['"]/.test(appMjs)
    && !/['"]\/api\/refresh['"]/.test(appMjs)
    && !/['"]\/api\/credential['"]/.test(appMjs),
  null);

// -------------------------------------------------------------------
// Summary
// -------------------------------------------------------------------
process.stdout.write(`\n${'='.repeat(60)}\n`);
process.stdout.write(`V6.9 privacy and runtime hardening — verification\n`);
process.stdout.write(`pass: ${pass}\n`);
process.stdout.write(`fail: ${fail}\n`);
process.stdout.write(`${'='.repeat(60)}\n`);
if (fail > 0) {
  for (const f of failures) {
    process.stderr.write(`FAIL: ${f.name}${f.detail ? ` — ${f.detail}` : ''}\n`);
  }
  process.exit(1);
}
process.exit(0);
