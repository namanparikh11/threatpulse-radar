# Deployment — Hostinger static hosting

> Drop-in deployment guide for **ThreatPulse Radar** on Hostinger's
> static hosting (or any Apache-based `public_html` host: shared
> hosting, subdomain, or subdirectory).
>
> Last verified against the v1.0 build (`dist/` with `base: './'`,
> `dist/.htaccess` present, 13/13 acceptance tests passing).

---

## 1. TL;DR

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

- Has **no backend** — there is nothing to configure on the
  server beyond the static files.
- Reads **no environment variables** at build time. There is
  nothing to swap per environment. If you ever need to point the
  app at a real API, that change goes in v2 (see
  `README.md` → "Planned data sources").
- Sends **no telemetry, no analytics, no third-party scripts**.
  Open DevTools → Network on the deployed page and confirm: only
  the bundle's own assets should be requested.
- Stores **no user accounts, cookies, credentials, or service
  worker data**. Uses `localStorage` **only** for a transparent
  1-hour vulnerability dataset cache under the versioned key
  `tpr:dataset:v1` (the v4 cache layer; no PII, no auth
  material, no third-party identifiers — just the previously
  fetched dataset envelope).

It's a portfolio piece. Treat it as read-only static HTML.

---

## 10. V4.1 public-demo honesty (what visitors will actually see)

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
