# Deployment — Netlify (with the v5.0 serverless proxy)

> Drop-in deployment guide for **ThreatPulse Radar** on
> **Netlify**, which is the v5.0 deployment target.
>
> The v5.0 deploy uses `netlify.toml` to wire a single
> serverless function (`/.netlify/functions/dataset`) that
> aggregates CISA KEV + NVD CVSS + FIRST EPSS server-side.
> The function runs on demand per request — no scheduled
> jobs, no persistent state, no credentials.
>
> Sections 2–8 below document the **v1.0–v4.1 Hostinger
> static-hosting** workflow, which is preserved as a
> fallback host (the `dist/.htaccess` file is still shipped
> with the bundle). V5.0 prefers Netlify, but a Hostinger
> static deploy still works for the v4.1 browser-direct
> demo if the function is not available.

---

## 0. V5.0 deployment (Netlify — recommended)

The v5.0 architecture is a single static site + one serverless
function. Netlify is the supported host; deploy via the Netlify
CLI or a Git-connected site.

### 0.1 TL;DR (v5.0)

```bash
# 1. Install the Netlify CLI (once)
npm i -g netlify-cli

# 2. Login + link to your site (first time only)
netlify login
netlify link                 # links to an existing site, or...

# 3. ...create a new site from this directory
netlify init                 # creates a draft site on Netlify

# 4. Deploy
netlify deploy --prod
# (or `netlify deploy` for a preview URL first)
```

That's it. `netlify.toml` at the project root tells Netlify:

- `command = "npm run build"` runs the Vite production build.
- `publish = "dist"` ships the built `dist/` as the site.
- `functions = "netlify/functions"` picks up the serverless
  function at `netlify/functions/dataset.mjs`.
- `[functions.dataset] node_bundler = "none"` skips esbuild
  bundling — the function is plain Node 20 ESM, no
  dependencies to bundle.

The site is live on a Netlify URL like
`https://<your-site>.netlify.app`. The function is reachable
at `https://<your-site>.netlify.app/.netlify/functions/dataset`.

### 0.2 What gets deployed (v5.0)

```
dist/                                    ← built by Vite, served as the site
├── .htaccess                            ← Apache config (Hostinger fallback; Netlify ignores it)
├── index.html                           ← SPA entry; references assets/ with relative URLs
├── radar.svg
└── assets/
    ├── index-*.css                      ← Tailwind output
    ├── index-*.js                       ← App code (v5.0: ~+1 kB for the proxy orchestration)
    ├── react-*.js
    ├── icons-*.js                       ← Lucide icons
    └── charts-*.js                      ← Recharts

netlify/functions/
└── dataset.mjs                          ← v5.0 serverless aggregator

netlify.toml                             ← Netlify config
```

The function is **separate from `dist/`** — Netlify deploys
both as one unit but they live in different runtime layers.
The browser hits the static `index.html` first, then the
function at `/.netlify/functions/dataset` for the live data.

### 0.3 Local development with the proxy

`npm run dev` runs Vite only — the function is **not** served.
On `http://localhost:5173` the dashboard works, but the
client-side `tryProxyFetch` will get a 404 and fall back to
the v4 browser-direct path (`proxyStatus: 'browser-direct'`).

To test the v5.0 proxy locally end-to-end:

```bash
# Option A: Netlify dev (Vite + Netlify Functions together)
npx netlify dev
# -> http://localhost:8888
# /.netlify/functions/dataset works here.

# Option B: Vite-only dev (function returns 404, client falls back)
npm run dev
# -> http://localhost:5173
# Dashboard still works. Header shows "Proxy: Netlify" only when
# the proxy is reachable; on Vite-only dev, no Proxy pill shows.
```

### 0.4 Verifying the v5.0 deploy

After `netlify deploy --prod`, open the deployed URL and
confirm:

- [ ] The dashboard loads. Title "ThreatPulse Radar",
      header pills render.
- [ ] DevTools → Network → `/.netlify/functions/dataset` returns
      `200` with a JSON body of shape
      `{ data: [...], source: "merged", mode: "live", ... }`.
      This is the proxy success path.
- [ ] The header shows a cyan **"Proxy: Netlify"** pill — the
      v5.0 transport indicator.
- [ ] The "Last refresh" pill ticks every fresh fetch.
- [ ] Hard refresh on `/` keeps the app working.
- [ ] Open DevTools → Network and confirm no requests to
      `cisa.gov`, `nvd.nist.gov`, or `api.first.org` from the
      browser — those calls are now made server-side by the
      function, not by the user. (This is the key v5.0
      property: the browser never touches the upstream feeds.)
- [ ] DevTools → Network → no 4xx / 5xx errors.
- [ ] DevTools → Application → Local Storage → `tpr:dataset:v1`
      appears after the first successful fetch. The v4 cache
      is still wired.

### 0.5 Verifying the v5.0 fallback path (Netlify)

To confirm the fallback path works (proxy down → browser-direct
→ mock), the simplest manual check is to break the function
endpoint in DevTools:

1. Open DevTools → Network.
2. Right-click the `/.netlify/functions/dataset` request →
   **Block request URL**.
3. Reload the page.
4. The dashboard should render with live CISA data (the
   browser-direct path), and the header should *not* show the
   "Proxy: Netlify" pill. Internally `proxyStatus` is
   `'browser-direct'`.

To confirm the *total* failure path (proxy down + browser-direct
down), block both `/.netlify/functions/dataset` *and* the three
upstream hosts. The dashboard should show the "Fallback Mode"
banner with `proxyStatus: 'unavailable'`. Restore Network access
and click "Retry live fetch" — the dashboard should come back
to live.

### 0.6 V5.0 deployment notes

- **No environment variables** need to be configured in
  Netlify's dashboard. The function reads no env vars. The
  `VITE_DATASET_PROXY_URL` client-side env var has a default
  of `/.netlify/functions/dataset` baked into
  `src/services/vulnerabilityService.ts`, so even an
  unconfigured deploy works out of the box.
- **No build hooks** or scheduled functions are configured.
  The function is read-only and runs on demand.
- **No CORS** issues — the function is at the same origin as
  the deployed site, so the browser hits it as a same-origin
  request. `Access-Control-Allow-Origin: *` is also set on
  the function response in case someone embeds the
  dashboard in an iframe.
- **The function is anonymous** — no auth, no rate limiting
  beyond Netlify's default 1.5M requests / month on the
  free tier. The dashboard is read-only public data, so
  this is fine.
- **Function cold start** is typically <500 ms on Netlify;
  the first request on a cold function may take ~1 s. The
  client-side 25 s timeout gives plenty of headroom.

### 0.7 V5.0.1 — function response is now CDN-cacheable

v5.0.1 is a performance-only patch. The function's
`Cache-Control` is now
`public, s-maxage=900, stale-while-revalidate=300`. The
behavior:

- **First visitor in a region** (cold CDN cache): the
  full CISA → NVD → EPSS pipeline runs once, taking
  5–15 s. The response is cached by Netlify's edge.
- **Subsequent visitors in the same region within 15 min**:
  the cached response is served in <100 ms. No upstream
  fetch, no function run, no cold start.
- **Visitor at minute 16+** (cache just expired):
  Netlify serves the stale response immediately AND
  triggers a background refresh. The next visitor after
  the refresh hits the fresh cache.
- **Visitor at minute 21+** (cache fully expired): the
  request waits for a fresh function invocation. Cold.

The dashboard's "Last refresh" pill shows the time since
the function *actually* ran (the `fetchedAt` is set
inside the function body), not the time the CDN served
the response. Freshness copy is preserved.

The "Refresh live data" button appends a unique
`?t=<timestamp>` query string when `forceRefresh: true`
is passed. The CDN treats this as a different URL and
re-runs the function — a manual refresh always fetches
fresh upstream data, regardless of the CDN cache state.

Netlify's edge cache is per-region. A new region with
no cached response pays the full upstream fetch cost
once, then serves from the regional edge thereafter.

### 0.8 V5.0.2 — optional server-side `NVD_API_KEY`

NVD's anonymous public endpoint allows 5 requests /
30 s. v5.0.2 makes this explicit:

- **Without `NVD_API_KEY` (default):** NVD chunks are
  fetched serially (`concurrency = 1`) to stay under
  the anonymous rate limit. The function still
  enriches every CVE, just one chunk at a time.
- **With `NVD_API_KEY` (optional):** NVD chunks fetch
  in parallel (`concurrency = chunks.length`),
  matching the v5.0.1 speed. NVD allows 50 req / 30 s
  with a key, so 10 parallel chunks are well under
  the limit.

**The key is server-side only.** It is read from
`process.env.NVD_API_KEY` inside the Netlify Function,
passed to NVD as a `?apiKey=<key>` query param, and is
**never** sent to the browser, never logged, never
included in the function response. The frontend is
unchanged in v5.0.2 — there is no `VITE_NVD_API_KEY`
or any other browser-exposed env var.

**Setting `NVD_API_KEY` on Netlify:**

```
# In the Netlify site dashboard:
#   Site settings → Environment variables → Add variable
#     Key:   NVD_API_KEY
#     Value: <your NVD API key>
#     Scopes: Functions
#              (NOT "Build" — the function reads it at
#               runtime, not at build time. Setting it
#               as a Build-scope var would be a no-op
#               and the key would still be safely
#               scoped to the function only.)
```

**Getting a key:** NVD API keys are free and issued at
<https://nvd.nist.gov/vuln/request-forms>. The v5.0.2
hardening does **not** require a key — the dashboard
works identically without one. The key is an optional
optimization for higher NVD throughput.

**Without a key, when NVD returns 429** (e.g. a fresh
demo with no localStorage cache yet), the function
returns a single concise reason instead of N repeated
chunk errors:

```
NVD rate limit reached (HTTP 429). NVD CVSS enrichment
is unavailable; severity falls back to CISA-derived
values for this refresh.
```

The dashboard's `NvdUnavailableBanner` renders this
reason verbatim. The banner now reads cleanly instead
of spilling 200+ characters of repeated errors.

---

## 1. TL;DR (v1.0–v4.1 Hostinger static-hosting — fallback)

1. `npm.cmd run build` — produces `dist/`.
2. Upload **the entire contents of `dist/`** (not the folder itself)
   into your Hostinger document root (`public_html/`, or a
   subfolder/subdomain root).
3. Visit the URL. Done.

No backend. No env vars. No build step on the server. No Node runtime
required at the host.

---

## 2. What to upload (the contents of `dist/`)

After `npm.cmd run build`, the `dist/` directory looks like this:

```
dist/
├── .htaccess                 ← Apache config (SPA fallback, caching, security headers)
├── index.html                ← HTML entry. References everything else with relative URLs.
├── radar.svg                 ← Favicon (referenced as ./radar.svg)
└── assets/
    ├── index-*.css           ← All CSS (Tailwind output, ~24 kB)
    ├── index-*.js            ← App code (~74 kB)
    ├── react-*.js            ← React + ReactDOM glue (~60 bytes — re-export only)
    ├── icons-*.js            ← Lucide icon set (~18 kB)
    └── charts-*.js           ← Recharts (~545 kB / 154 kB gzipped)
```

The fingerprint hashes (e.g. `index-CrghLoDm.js`) change every time
source changes, so the filenames are content-addressed — safe to
cache forever. The entry `index.html` is **not** hashed, so it always
re-fetches and pulls in the new hashes.

**Upload rules:**

- Upload the **contents** of `dist/`, not `dist/` itself. Your
  `public_html/` should end up with `.htaccess` and `index.html` at
  its top level, **not** inside a `dist/` subfolder.
- Upload **all 6 files**, including the hidden `.htaccess`. Some
  FTP clients hide dotfiles by default — see troubleshooting
  below.
- Do **not** upload `node_modules/`, `src/`, `scripts/`, or any
  other top-level project folder. Only `dist/` ships.
- Do **not** upload `package.json`, `package-lock.json`, or
  `vite.config.ts` to the host. The build is already done; the
  server just serves static files.

---

## 3. Where to upload it (Hostinger specifics)

### A. Subdomain at the document root (most common)

Hostinger's free subdomain (`yourname.hostinger-site.com`) or any
custom subdomain (`radar.yourdomain.com`) is typically served from
`public_html/` directly.

Steps:

1. Hostinger hPanel → **Websites** → pick the domain → **File Manager**.
2. Open `public_html/`.
3. **Delete any default files** (`default.php`, `index.html`,
   `cgi-bin/`, etc.) that Hostinger may have left behind. Otherwise
   your upload may collide with them.
4. Drag-and-drop or upload the **6 files** from `dist/` into
   `public_html/`.
5. (If the File Manager hides dotfiles: click **Settings** in the
   top right and enable **Show hidden files (dotfiles)** before
   uploading `.htaccess`.)
6. Visit your subdomain. The dashboard should load.

### B. Subdirectory under an existing domain

If you want it served at `yourdomain.com/radar/`:

1. In File Manager, create a folder `radar/` inside `public_html/`.
2. Upload the **6 files** from `dist/` into `public_html/radar/`.
3. Open `public_html/radar/.htaccess` in the editor and change
   `RewriteBase /` to `RewriteBase /radar/`. Save.
4. Visit `https://yourdomain.com/radar/`. The dashboard should load.

The `base: './'` setting in `vite.config.ts` makes this case work
out of the box — no Vite rebuild required.

### C. Custom domain pointed at Hostinger

Same as A or B, but in the Hostinger dashboard **point** the custom
domain at the right document root first. The static file upload
steps are identical.

---

## 4. Why `base: './'` is correct for both subdomain and subpath

The Vite build option `base: './'` makes the built `index.html`
reference its assets with **relative** URLs:

```html
<script type="module" crossorigin src="./assets/index-CrghLoDm.js"></script>
<link rel="stylesheet" crossorigin href="./assets/index-D3L73znI.css">
<link rel="icon" type="image/svg+xml" href="./radar.svg">
```

This means:

- On a subdomain (`https://radar.example.com/`) — the browser
  resolves `./assets/...` to `https://radar.example.com/assets/...`.
  Works.
- On a subpath (`https://example.com/radar/`) — the browser
  resolves `./assets/...` to `https://example.com/radar/assets/...`.
  Works.
- On `localhost` (`npm run preview`) — `./assets/...` resolves
  relative to the preview URL. Works.

If we had left the default `base: '/'`, subpath deployment would
break because the browser would look for assets at
`https://example.com/assets/...` (one level too high) and 404.

**Don't change this setting** unless you're certain the host
URL never changes.

---

## 5. The `.htaccess` file (what it does and when to edit it)

`dist/.htaccess` is a 3 KB Apache config. It does three things:

1. **SPA fallback** — any URL that doesn't match a real file or
   directory is rewritten to `/index.html`. ThreatPulse Radar is a
   single-page app with no client-side routes today, so this is
   defensive. It also makes the bundle future-proof for any
   deep-link state added in v2.
2. **Long-cache for fingerprinted assets** — `*.js`, `*.css`,
   `*.svg`, images, and fonts are cached for 1 year. The entry
   `index.html` is set to `access plus 0 seconds` so deploys are
   picked up immediately.
3. **Security headers** — `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: strict-origin-when-cross-origin`, and a
   minimal `Permissions-Policy`. CSP and HSTS are commented out
   (uncomment on HTTPS once you confirm the bundle is fully
   self-hosted — see the comments in the file).

When to edit it:

- **Subpath deployment** (case B above) — change `RewriteBase /`
  to `RewriteBase /your-subdir/`.
- **HTTPS-only** — uncomment the `Content-Security-Policy` and
  `Strict-Transport-Security` lines. The default CSP allows
  only `'self'` plus inline styles (Tailwind injects some). It
  will not break this app because all data is local.
- **Different cache needs** — adjust the `ExpiresByType` lines.

If you ever need to remove the file, the app will still work for
`/` requests but will 404 on any deep URL refresh. Acceptable for
this app today, not acceptable if you add client-side routes later.

---

## 6. Troubleshooting

### 6.1 Blank page (white screen, no errors in the browser)

Most likely causes, in order:

1. **You uploaded the `dist/` folder instead of its contents.** Your
   `public_html/` now has `dist/index.html` and the URL resolves
   to `public_html/index.html` (which doesn't exist). Fix: move
   the files up one level, or re-upload with the folder structure
   flattened.

2. **`.htaccess` wasn't uploaded.** Apache falls back to default
   handling. The app should still load on `/`, but if your host
   has stricter default rules you can get a 403. Fix: re-upload
   the `.htaccess` file, ensuring your FTP client is set to show
   and send dotfiles.

3. **`base: '/'` was reintroduced** (someone reverted `vite.config.ts`
   to remove the `base: './'` line). Fix: re-add `base: './'`,
   rebuild, re-upload the new `dist/`.

4. **Browser is serving a cached old `index.html`** with absolute
   `/assets/...` paths that don't exist at the new URL. See
   section 6.4.

5. **Console says something like `Refused to apply style from ...`**
   or **`Refused to execute script from ...`**. This is a CSP
   issue — uncomment the `Content-Security-Policy` line in
   `.htaccess` only after confirming the assets are served from
   the same origin (no mixed content).

Quickest diagnostic: open DevTools → **Network** tab, hard-refresh
(`Ctrl+Shift+R`), and check whether the requests for
`/assets/index-*.js` and `/radar.svg` return `200` or `404`. The
first failed request tells you which problem you have.

### 6.2 Assets not loading (404 on `assets/...`)

Same root cause family as 6.1, but with a clearer symptom. Check:

- The file `dist/assets/index-CrghLoDm.js` (or whatever the
  current hash is) exists at `public_html/assets/`. If not, the
  `assets/` folder wasn't uploaded.
- The browser's Network tab shows the request URL. If it shows
  `/assets/...` (absolute) and you're on a subpath deployment,
  `vite.config.ts` was rebuilt with the default `base: '/'`. Fix
  by re-adding `base: './'` and rebuilding.
- If it shows `https://wrong-host.example/assets/...`, the
  absolute URL is hard-coded somewhere — search the source for
  `/assets/` (should only appear in `vite.config.ts` and
  `public/`).

### 6.3 Wrong folder uploaded

The most common mistake: drag-and-dropping the *parent* `dist/`
folder into `public_html/`, which produces
`public_html/dist/index.html` — and the browser sees nothing.

How to check: in File Manager, look at the top level of
`public_html/`. You should see **directly** at that level:
`index.html`, `radar.svg`, `.htaccess`, and the `assets/` folder.
If you see a single `dist/` folder containing them, move its
contents up one level and delete the now-empty `dist/` folder.

Also watch out for `dist.zip` (some file managers keep the
original archive). That should not be served — delete it.

### 6.4 Browser cache (stale `index.html`)

The single most common cause of "I uploaded the new version but
I'm still seeing the old one."

Why it happens: your `index.html` is set to
`ExpiresByType text/html "access plus 0 seconds"` *on the server*,
but the **browser** has its own cache that may have its own copy
from a previous visit. Browsers cache HTML aggressively, and a
soft refresh (F5) re-uses the cached `index.html`, which still
points at the *old* fingerprinted asset URLs — so the assets 404.

Fixes (in order of how aggressive they are):

1. **Hard refresh** — `Ctrl+Shift+R` (Windows/Linux) or
   `Cmd+Shift+R` (macOS). Reloads the page ignoring cache.
2. **DevTools with cache disabled** — DevTools → Network tab →
   check **Disable cache** (only works while DevTools is open).
3. **Browser-level clear** — clear site data for the deployed
   domain. Chrome: DevTools → Application → Clear storage →
   **Clear site data**.
4. **Incognito window** — fastest sanity check. If the new
   version loads in Incognito, the issue is your normal browser's
   cache.
5. **Query-string bypass** — open
   `https://your-domain/?v=2` to force the browser to revalidate.
   Useful for a quick smoke test from your phone.

If you want to push a hard-cache-bust to *all* users (not just
yourself), bump the entry `index.html` filename or add a
`Cache-Control: no-store` header via `.htaccess` (then remember
to remove it later — it kills performance).

### 6.5 Other common gotchas

- **Mixed content** — your host serves HTTPS but one of the
  assets is being requested over HTTP. Shouldn't happen with
  this app (all assets are relative), but check the Network tab
  for any `http://` requests.
- **Forced HTTPS redirect loop** — Hostinger sometimes adds a
  global redirect. If you see `ERR_TOO_MANY_REDIRECTS`, the
  `.htaccess` rewrite and the host's HTTPS redirect are
  conflicting. The default `.htaccess` here doesn't force HTTPS,
  so this would only happen if Hostinger is configured oddly.
- **File permissions** — if you upload via FTP as one user and
  the server runs as another, the files may not be readable.
  In File Manager, right-click each file → **Permissions** →
  set to `644` (files) and `755` (folders).
- **`radar.svg` 404** — favicon missing. Make sure the
  `radar.svg` file at `dist/radar.svg` was uploaded (it sits
  next to `index.html`, not inside `assets/`).

---

## 7. Re-deploying (updates)

When you change source and want to push a new build:

1. `npm.cmd run build` — produces a new `dist/` with new
   fingerprint hashes.
2. Upload the new `dist/` contents over the old ones.
3. Hard-refresh the browser (section 6.4).

Because the asset hashes change, the browser will fetch the new
JS/CSS automatically once it gets the new `index.html`. Old
hashed assets can stay on the server for a while — they're not
referenced anymore, but they're harmless. To clean up: delete
the entire `public_html/assets/` folder and re-upload.

---

## 8. Verification checklist (after first deploy)

Open the deployed URL and confirm:

- [ ] The hero renders — title "ThreatPulse Radar", subtitle,
      two badges (Portfolio Project / Mock Data Mode), three
      status pills.
- [ ] Browser tab title is `ThreatPulse Radar`.
- [ ] Favicon (`radar.svg`) shows in the tab.
- [ ] Typing `fortinet` in the search box filters to only
      Fortinet rows.
- [ ] Clicking a row opens the detail drawer.
- [ ] DevTools console has **no errors** and **no 404s**.
- [ ] A hard refresh on `/` keeps the app working.
- [ ] The bundle's transferred size is roughly 184 kB gzipped
      (DevTools → Network → check the bottom status bar).

---

## 9. What this deployment does NOT include

For the avoidance of doubt, the deployed bundle:

- Has **no traditional backend** — the v5.0 deploy is one
  read-only serverless function plus a static site. There
  is no database, no auth, no business logic, no
  persistent state, and no scheduled jobs. The function is
  invoked on demand per request and does not retain any
  data between invocations.
- Reads **no environment variables** at build time. The
  single optional client-side env var
  (`VITE_DATASET_PROXY_URL`) has a baked-in default of
  `/.netlify/functions/dataset` and is documented but not
  required. The function itself reads no env vars.
- Sends **no telemetry, no analytics, no third-party
  scripts** from the browser. (The server-side function
  makes outbound HTTP requests to CISA, NVD, and FIRST
  EPSS — those are the *upstream data sources*, not
  third-party trackers, and they are visible in the
  function's own logs.)
- Stores **no user accounts, cookies, credentials, or
  service worker data**. Uses `localStorage` **only** for
  a transparent 1-hour vulnerability dataset cache under
  the versioned key `tpr:dataset:v1` (the v4 cache layer;
  no PII, no auth material, no third-party identifiers —
  just the previously fetched dataset envelope).

It's a portfolio piece. Treat it as read-only static HTML
plus one read-only function.

---

## 10. V4.1 / V5.0 public-demo honesty (what visitors will actually see)

A static public deployment of a "live" data dashboard has a real
honesty problem. The deployed bundle has no backend and no proxy,
so it depends on each of the three data feeds (CISA KEV, NVD,
FIRST EPSS) continuing to allow direct browser requests.
**That is not a guarantee.** CORS policies, anonymous rate
limits, geo restrictions, and upstream outages can each make a
provider unreachable from a visitor's browser.

This is expected for v4.1, and the dashboard is intentionally
transparent about it:

- **CISA KEV unreachable** → the header shows an amber
  "Fallback Mode" badge, the source pill reads "Source: mock
  (fallback)", and a "Live CISA KEV feed unavailable — showing
  mock data" banner appears above the stats with the failure
  reason and a "Retry live fetch" button. The curated 60-record
  mock dataset is rendered; filtering, sorting, search, charts,
  and the detail drawer all work identically against it.
- **NVD or EPSS unreachable** (CISA succeeded) → the CISA data
  is still shown. An amber "NVD: unavailable" or "EPSS:
  unavailable" pill appears in the header, and a soft banner
  above the stats explains the partial outage. The page never
  *claims* enrichment that didn't happen.
- **Cached data** (v4) → a "Cache: fresh" / "Cache: stale" pill
  in the header and a "Cached data" banner above the stats
  show the relative and absolute time of the last upstream
  fetch, plus a manual "Refresh live data" button. The
  provider-status banners above are preserved through the
  cache envelope, so cached data is never indistinguishable
  from a successful live load.

**No API keys, secrets, or tokens are ever embedded in the
frontend bundle.** A static `dist/` is a public artifact the
moment the site is deployed; shipping a key in it would ship a
public credential. The NVD API key path is intentionally not
implemented in v4.1; the 5-req/30s anonymous rate limit is a
price worth paying for not leaking a secret.

**A future v5 could add a thin backend or serverless proxy**
that aggregates CISA + NVD + FIRST EPSS server-side and exposes
a single CORS-safe JSON endpoint. That would fix the first-load
NVD latency and remove the CORS-failure surface for the public
demo. **v4.1 does *not* add the backend** — it is an explicit
v5 milestone, and the deployment strategy above is unchanged.

---

_Made with care — defensive only._
