# V6.0 — Deployment

The V6.0 architecture has THREE separate Netlify
environments:

1. The **public ThreatPulse Radar site** (unchanged from
   V5.7; hosts the V5.7 dashboard, the V6.0 OSV ingestion
   pipeline, and the V6.0 background function).
2. The **private sync gateway** (a separate Netlify site
   that exposes the authenticated `/private/v1/*` routes).
3. The **consumer's site** (whatever the consumer's product
   is; not part of the ThreatPulse Radar repository).

The split between the public site and the private gateway is
the V6.0 amendment #1: the canonical baseline is private; the
gateway is what authenticated callers talk to.

This document covers the production environment variables,
the Blob store layout, the function configurations, and the
publish-time verification steps.

## 1. Public site

The public site is the V5.7 site plus the V6.0 OSV ingestion
pipeline. It owns the `tpr-baseline` Blob store.

### Environment variables (public site)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_REFRESH_TRIGGER_SECRET` | yes | Shared secret used by the Scheduled Function to invoke the Background Function. Long random string. |
| `THREATPULSE_BASELINE_SITE_ID` | yes (for the private gateway below) | The public site's Netlify site ID. Used by the private gateway to read the `tpr-baseline` store cross-site. |
| `THREATPULSE_BLOBS_ACCESS_TOKEN` | yes (for the private gateway below) | A Netlify Blobs access token scoped to the `tpr-baseline` store on the public site. Created in the Netlify UI under **Site settings → Blobs → Access tokens**. |
| `THREATPULSE_OSV_ECOSYSTEMS` | no | Optional JSON override of `config/osv-ecosystems.json`. Same shape. When set, the env var wins; when unset, the file is used. |

### Environment variables that MUST NOT be set

- `THREATPULSE_CREDENTIAL_PEPPER` — the pepper is for the
  private gateway only. Setting it on the public site has
  no effect (the public site never reads credentials) and
  increases the attack surface.

### Functions (public site)

| File | Netlify kind | Path |
| --- | --- | --- |
| `netlify/functions/dataset.mjs` | HTTP | `/.netlify/functions/dataset` (V5.7 dashboard) |
| `netlify/functions/refresh-dataset-background.mjs` | Background | `/.netlify/functions/refresh-dataset-background` (V5.2) |
| `netlify/functions/refresh-dataset-scheduled.mjs` | Scheduled | cron `*/30 * * * *` (V5.2) |
| `netlify/functions/refresh-baseline-scheduled.mjs` | Scheduled | cron `0 * * * *` (V6.0 thin launcher) |
| `netlify/functions/refresh-baseline-background.mjs` | Background | `/.netlify/functions/refresh-baseline-background` (V6.0) |

The V5.2 and V6.0 pipelines are independent. The V5.2
pipeline feeds the V5.7 dashboard; the V6.0 pipeline feeds the
canonical baseline. A failure in one does not block the
other.

### Blob stores (public site)

| Store name | Contents |
| --- | --- |
| `tpr-dataset` | V5.2 latest dataset + refresh lock (unchanged) |
| `tpr-vulnrichment` | V5.5 SSVC cache (unchanged) |
| `tpr-github-advisory` | V5.6 GitHub Advisory cache (unchanged) |
| `tpr-baseline` | **V6.0** canonical baseline (see layout below) |

### `tpr-baseline` layout

```
tpr-baseline/
  manifests/
    latest.json                 ← THE atomic commit point (mutable)
    versions/{version}.json     ← immutable version manifests
  objects/sha256/<hex>.json.gz   ← immutable content-addressed shards
  deltas/{from}__to__{to}.json   ← immutable deltas
  credentials/{keyId}           ← stored HMAC for each consumer credential
  osv-bootstrap-state           ← orchestrator journal (private to the publisher)
  source-registry               ← static source registry
  source-health                 ← aggregate source health
```

**Do not write to `tpr-baseline` from anything other than the
V6.0 publisher functions.** The publisher is the only
component that should be writing to it. An operator that
needs to read the store can use the Netlify Blobs UI; an
operator that needs to write (e.g., to add a credential) can
do so via the UI as well.

## 2. Private sync gateway

The private sync gateway is a SEPARATE Netlify site. It is
the only component that holds the credential pepper and the
cross-site Blob access token. It does NOT talk to OSV; it
only reads from the public site's `tpr-baseline` store.

### Environment variables (private gateway)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_BASELINE_SITE_ID` | yes | The public site's Netlify site ID. |
| `THREATPULSE_BLOBS_ACCESS_TOKEN` | yes | A Netlify Blobs access token scoped to `tpr-baseline` on the public site. |
| `THREATPULSE_CREDENTIAL_PEPPER` | yes | The HMAC pepper. Long random string. MUST be identical to the value used by the operator script when issuing credentials. |

### Environment variables that MUST NOT be set

- `THREATPULSE_REFRESH_TRIGGER_SECRET` — the trigger secret
  is for the public-site Background Function only. The
  private gateway has no scheduled function.
- `THREATPULSE_OSV_ECOSYSTEMS` — the private gateway does
  not ingest; it only reads.

### Function (private gateway)

| File | Netlify kind | Path |
| --- | --- | --- |
| `netlify/functions/private-sync-gateway.mjs` | HTTP | `/private/v1/*` (mounted via the function's `config.path` export) |

The function's `config.rateLimit` is the initial rule:
`windowLimit: 200`, `windowSize: 60`, `aggregateBy: ['ip',
'domain']`. This is a reasonable initial cap. Per-credential
hard quotas are deferred.

### Blobs (private gateway)

The private gateway does NOT own any Blob store. It reads
from the public site's `tpr-baseline` store via the
cross-site env vars. There is nothing to back up on the
private gateway's side; the source of truth is the public
site.

## 3. Consumer's site

The consumer is a third-party product. It uses the
[`client/consumer-client.mjs`](../../client/consumer-client.mjs)
reference client (or its own implementation) to authenticate
to the private gateway and pull the baseline.

### Environment variables (consumer's site)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_GATEWAY_URL` | yes | The private gateway's base URL (no trailing slash). |
| `THREATPULSE_CONSUMER_CREDENTIAL` | yes | The consumer's HMAC credential (`tpr_…`). Loaded from the consumer's secret manager; never committed. |

The consumer's local store is whatever satisfies the
contract documented in
[`client/contracts.md`](../../client/contracts.md). The
default is a filesystem path.

## 4. netlify.toml — public site

The V6.0 schedule and function declarations live in the
public site's `netlify.toml`:

```toml
[build]
  command = "npm run build"
  publish = "dist"
  functions = "netlify/functions"

[functions]
  node_bundler = "esbuild"

[functions.refresh-baseline-scheduled]
  schedule = "0 * * * *"

[functions.dataset]

[functions.refresh-dataset-background]

[functions.refresh-dataset-scheduled]
  schedule = "*/30 * * * *"
```

The function bundler is `esbuild` so that the `_shared/*.mjs`
modules ship inside each function's bundle (the v5.2.1 fix).
The schedule is hourly (decision #1). The V5.2 30-minute
schedule is unchanged.

## 5. Function configuration — private gateway

The private gateway function's `config` export is:

```js
export const config = {
  path: '/private/v1/*',
  rateLimit: {
    windowLimit: 200,
    windowSize: 60,
    aggregateBy: ['ip', 'domain'],
  },
};
```

Per amendment #5, rate limits and path are exported on the
function, NOT in `netlify.toml`. The Netlify CLI reads the
export and applies it at deploy time.

## 6. Cross-site access token

The `THREATPULSE_BLOBS_ACCESS_TOKEN` is a token scoped to the
`tpr-baseline` store on the public site. To create one:

1. In the Netlify UI for the **public** site, go to
   **Site settings → Blobs**.
2. Click **Create access token**.
3. Scope: **Store: tpr-baseline**, **Permissions: read**.
   (The private gateway only reads.)
4. Copy the token into the private gateway's env vars.
   The token is shown ONCE; lose it and you must rotate.

**Never** put this token in the public site's env vars. The
public site does not need it (it has direct store access via
its own runtime context). The token only lives on the
private gateway.

**Never** put this token in the consumer's environment. The
consumer authenticates to the gateway with the HMAC
credential, not with cross-site access.

## 7. Cron timing

The V6.0 cron is `0 * * * *` (top of every hour, UTC). The
first run on a fresh site is a bootstrap: it processes the
entire OSV corpus across many Background Function
invocations (each bounded to a slice by `maxRecords` and
`timeBudgetMs`). After bootstrap, each run is incremental.

If the cron tick fires while a previous Background Function
is still running, Netlify queues the new tick. There is no
overlap; the orchestrator's resume cursor ensures correctness
either way.

## 8. Deploy-time verification

After deploying, verify in order:

1. **The scheduled function exists and is wired.**
   In the Netlify UI for the public site, go to
   **Functions → refresh-baseline-scheduled** and confirm
   the schedule is `0 * * * *`. There is no log yet (cron
   hasn't fired since the deploy).

2. **The trigger secret is configured.**
   In the Netlify UI for the public site, go to
   **Site settings → Environment variables** and confirm
   `THREATPULSE_REFRESH_TRIGGER_SECRET` is set. Its value is
   not visible; only its presence.

3. **The cross-site access token is configured on the
   gateway.** In the Netlify UI for the private gateway,
   confirm `THREATPULSE_BASELINE_SITE_ID` and
   `THREATPULSE_BLOBS_ACCESS_TOKEN` are set.

4. **The pepper is configured on the gateway.** Confirm
   `THREATPULSE_CREDENTIAL_PEPPER` is set.

5. **Wait for the first cron tick.** Within an hour of
   deploying, the scheduled function will fire. It will POST
   to the background function with the trigger secret. The
   background function logs the result. After an hour, look
   in **Functions → refresh-baseline-background → Logs** for
   a line like:
   ```
   [v6.0 background refresh] iterations=N totalProcessed=M publishedCount=K elapsedMs=…
   ```

6. **Confirm a manifest exists.** Call the gateway with a
   valid credential:
   ```bash
   curl -i -H "Authorization: Bearer tpr_…" \
     https://your-private-gateway.example.com/private/v1/manifest
   ```
   The response should be 200 OK with a JSON body that has
   `baselineVersion`, `canonicalContentHash`, `shards`, and
   `stats`.

7. **Confirm a shard is fetchable.**
   ```bash
   curl -i -H "Authorization: Bearer tpr_…" \
     "https://your-private-gateway.example.com/private/v1/shard?key=objects/sha256/<hex>.json.gz"
   ```
   The response should be 200 OK with `Content-Type:
   application/octet-stream` and `Content-Encoding: gzip`.

8. **Confirm an anonymous request is rejected.**
   ```bash
   curl -i https://your-private-gateway.example.com/private/v1/manifest
   ```
   The response should be 401 Unauthorized.

9. **Confirm the public dashboard is unchanged.** Visit the
   public site's URL. The V5.7 dashboard should render with
   no new errors. The V6.0 changes are isolated to the
   publisher and the gateway; the dashboard does not touch
   the canonical baseline.

## 9. Rollback

The V6.0 changes are additive. To roll back:

1. Revert the V6.0 commits in reverse order (last-in,
   first-out).
2. Redeploy.

The V5.2 / V5.5 / V5.6 / V5.7 functions and Blob stores are
untouched. The V5.7 dashboard is unaffected by the V6.0
publisher running or not running.

The V6.0 changes do NOT delete the V5.2 `latest-dataset`
Blob. If a V6.0 deploy runs into a problem, the V5.2
pipeline can continue independently.

## 10. Failure modes and recovery

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| No V6.0 baseline after an hour | Trigger secret mismatch | Check the public-site logs for the background function's 401. Fix the env var. |
| Gateway returns 500 with "store unavailable" | Cross-site env vars missing or wrong site ID | Confirm `THREATPULSE_BASELINE_SITE_ID` and `THREATPULSE_BLOBS_ACCESS_TOKEN` on the gateway. |
| Gateway returns 401 for all requests | Pepper mismatch or credentials not yet written | Confirm `THREATPULSE_CREDENTIAL_PEPPER` is the same value used to generate the credentials. Confirm at least one `credentials/<keyId>` Blob exists. |
| Manifest hash mismatch on consumer | Manifest was tampered with, or the consumer is verifying against a cached version | Re-pull the manifest. Consumers should not cache the manifest hash; the publisher's hash is authoritative. |
| Background function runs but publishes nothing | The orchestrator's bootstrap state shows `status: 'idle'` and no records to process. This is normal for an incremental run. | No action. The next cron tick will process any new OSV records. |
| Bootstrap state stuck in `running` | The previous Background Function was killed mid-run. The orchestrator's resume cursor handles this on the next tick. | No action. The next tick resumes from the cursor. |

## 11. Upgrades

To upgrade from V5.7 to V6.0:

1. Deploy the V6.0 code to the public site. The V5.7 dashboard
   is unaffected (the V6.0 code is additive).
2. Wait for at least one successful background run (logs).
3. Deploy the V6.0 private gateway. Configure the cross-site
   env vars and the pepper.
4. Issue a credential to your first consumer.
5. The consumer pulls the baseline via the reference client
   or its own implementation.
6. The public dashboard continues to work as before.

To upgrade from V6.0.x to V6.0.y (a future V6.0 minor):

- The schemas are versioned. A new schema is additive;
  consumers that don't read the new fields continue to work.
- A breaking change to the schema requires a major version
  bump and a separate migration guide.
- The Blob layout is stable; no migrations needed.
- The credentials are unchanged; a new consumer is not needed
  to upgrade the publisher.

## 12. What to NOT do

- Do NOT add a public endpoint that reads the canonical
  baseline. The whole point of V6.0 is that the baseline is
  private.
- Do NOT add a public read API for the baseline. The
  consumer client is the supported way to read it.
- Do NOT change the credential format without a major
  version bump and a clear migration path.
- Do NOT use the consumer's HMAC credential for the
  publisher's trigger secret, or vice versa. They are
  different secrets with different scopes.
- Do NOT log the pepper, the trigger secret, the
  cross-site access token, or any consumer's HMAC
  credential. The function logs and the consumer client
  both keep these out of the logs.
