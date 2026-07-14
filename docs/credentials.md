# V6.0 — Credentials

The V6.0 private sync gateway uses HMAC-SHA256 credentials to
authenticate callers. This document covers the credential
format, how to issue one, how to rotate it, and how to revoke
it.

## Credential format

Every credential is a string of the form

```
tpr_<keyId>_<randomSecret>
```

- `tpr_` — the literal prefix; identifies this as a
  ThreatPulse Radar credential. The gateway rejects any
  Authorization header that does not start with `Bearer tpr_`.
- `<keyId>` — a 1–64 character identifier from the safe
  alphabet `A–Z`, `a–z`, `0–9`, `-`. The underscore is
  **deliberately excluded** because the random secret is
  base64url-encoded (which uses `_`) and the underscore is the
  separator in the credential string. Including `_` in the
  keyId alphabet would make the credential ambiguous to parse.
- `<randomSecret>` — 32 random bytes encoded as base64url
  (43 characters, no padding). The random secret is the
  secret half; the keyId is the look-up half.

The full credential is sent in the `Authorization` header:

```
Authorization: Bearer tpr_<keyId>_<randomSecret>
```

## Where credentials are stored (V6.0 deployment-hardened)

Credentials live in a **gateway-local Netlify Blobs store**,
called `tpr-private-credentials`. The store is created on
the **GATEWAY** site (not the public site) and is read by
the gateway via the gateway's own local Netlify Blobs
runtime context — no siteID, no access token, no
cross-site access.

```
tpr-private-credentials/      ← lives on the GATEWAY site
  credentials/<keyId>   →  { hmac, createdAt, label? }
```

The store is intentionally separate from the public site's
`tpr-baseline` store (the canonical baseline data lives on
the public site and is read by the gateway via cross-site
env vars; see `docs/deployment.md`).

Why a gateway-local store:

- The gateway is the ONLY component that needs to verify
  a consumer credential. Putting the store on the
  gateway means the public-site operator does not have
  read access to the credential records, and a compromise
  of the public site cannot enumerate or attempt to
  read credential HMACs.
- The gateway's Netlify runtime has direct local-context
  access to its own Blobs store. No token, no site ID,
  no cross-site round trip. The auth check stays
  server-side and uses the gateway's own authentication
  boundary.
- The blast-radius argument is reversed: a token scoped
  to the public-site `tpr-baseline` cannot authorize
  reading the gateway's `tpr-private-credentials`. The
  two stores are in two different Netlify sites and are
  gated by two different operator-controlled boundaries.
- Audit and rotation can be done independently of the
  public-site baseline.

The store is created on the gateway site in the Netlify
UI (Site settings → Blobs → store list). The name
`tpr-private-credentials` is fixed by the gateway's
`CREDENTIALS_STORE_NAME` constant in
`netlify/gateway/src/_shared/baselineStore.mjs`.

## How the gateway verifies a credential

For each request, the gateway:

1. Reads the `Authorization: Bearer tpr_…` header.
2. Parses the credential into `{ keyId, randomSecret }`.
3. Reads `credentials/<keyId>` from the GATEWAY-LOCAL
   `tpr-private-credentials` Blob store (NOT from the
   public site's `tpr-baseline`). The stored value is the
   `HMAC-SHA256(THREATPULSE_CREDENTIAL_PEPPER, keyId + ":" + randomSecret)`
   digest, as lowercase hex with no prefix. The read uses
   the gateway's local Netlify Blobs runtime context — no
   env var, no token, no cross-site access.
4. After the credential is verified, the gateway reads
   the requested baseline artifacts from the public
   site's `tpr-baseline` store via cross-site env vars
   (`THREATPULSE_BASELINE_SITE_ID` and
   `THREATPULSE_BLOBS_ACCESS_TOKEN`).
4. Computes the same HMAC of the provided credential.
5. Compares the two digests in constant time using
   `crypto.timingSafeEqual` over the 32-byte SHA-256 output
   (after hex decode). The comparison is constant-time over
   the full 32 bytes regardless of input length, so a
   wrong-length credential cannot be used as a side channel.
6. If the digests match, the request is authenticated. The
   keyId is recorded for operator-side audit logs (never in
   client-visible responses).

The pepper is `THREATPULSE_CREDENTIAL_PEPPER` on the private
gateway's Netlify site. It is a server-side salt that prevents
an attacker with read access to the Blob store from using the
stored HMAC directly — they would also need the pepper, which
lives only in the gateway's environment.

## Issuing a credential

There is no UI in V6.0 for issuing credentials. Operators do
this in three steps.

**Step 1.** Generate a credential with the operator script
(lives in the deploy tooling; not committed):

```js
import { generateCredential } from './netlify/functions/_shared/credentials.mjs';

const pepper = process.env.THREATPULSE_CREDENTIAL_PEPPER;
const c = generateCredential({ pepper, keyId: 'consumer-prod-2026q3' });
console.log(c.credential);
// → tpr_consumer-prod-2026q3_<43-char base64url secret>

console.log(c.hmac);
// → <64-char lowercase hex>  ← this is what you store
```

**Step 2.** Hand the `credential` string to the consumer.
**Never** send it over email, chat, or any other channel that
the consumer's threat model does not already cover. The
consumer's job is to put it in their secret manager.

**Step 3.** Write the `hmac` to the GATEWAY-LOCAL
`tpr-private-credentials` Blob store at
`credentials/<keyId>`. The store lives on the gateway site
(NOT the public site) and is read by the gateway's local
Netlify Blobs runtime context. In the Netlify UI for the
**gateway** site, the Blobs tab lets you create a key with
a JSON value:

```json
{ "hmac": "<the 64-char hex from step 1>",
  "createdAt": "2026-07-12T20:00:00.000Z",
  "label": "consumer-prod-2026q3" }
```

The `label` is operator-facing only. The `createdAt` is also
operator-facing; the gateway does not currently enforce
expiration. (Credential auto-expiry is deferred to a future
version.)

**Step 4.** Confirm by calling the gateway:

```bash
curl -i -H "Authorization: Bearer tpr_..." \
  https://your-private-gateway.example.com/private/v1/manifest
```

A `200 OK` means the credential is valid and the gateway can
read the store. A `401 Unauthorized` means the credential
parses but the stored HMAC does not match — usually a typo in
the Blob value.

## Storing credentials on the consumer side

The credential grants read access to your private baseline.
Treat it like a database password or an API key:

- Store in a secret manager (AWS Secrets Manager, GCP Secret
  Manager, HashiCorp Vault, 1Password, etc.).
- Never commit it to source control, even in a `.env.example`.
- Never log it. The consumer's HTTP fetcher should use a
  request library that supports redacting the
  `Authorization` header from logs.
- Never include it in error reports or stack traces. The
  consumer's `Authorization: Bearer …` header should be
  considered sensitive by every layer that handles it.

The V6.0 reference consumer
([`client/consumer-client.mjs`](../../client/consumer-client.mjs))
takes the credential as a constructor argument and never
writes it to disk. The local store only sees opaque shard
keys; the credential never appears in a local file.

## Rotating a credential

Rotation is "issue a new one, switch the consumer, delete the
old one." Per-credential auto-rotation is not in V6.0.

**Step 1.** Issue a new credential with a new `keyId` (or
re-use the old keyId — the gateway reads by keyId, so reusing
it is fine, just add a `-v2` suffix to the human label).

**Step 2.** Add the new keyId to the consumer's secret
manager. Wait for the consumer to start using it. (How
"wait" is implemented is the consumer's problem; a typical
strategy is a short overlap window where both credentials
are valid, then a switch, then a check that the old
credential is no longer used, then revocation.)

**Step 3.** Delete `credentials/<old-keyId>` from the Blob
store. The gateway's next request with the old credential
gets a 401.

The old credential's `randomSecret` is **not** enough to
authenticate. The HMAC requires the random secret AND the
pepper. Deleting the stored digest is sufficient to revoke
the credential; the random secret can be discarded.

## Revoking a credential

Revocation is the same as the rotation step 3: delete the
`credentials/<keyId>` Blob. The gateway will return 401 for
subsequent requests with that credential.

There is no soft revocation in V6.0. The choice is binary:
the credential is valid (Blob exists) or it is not (Blob
deleted). For emergency revocation, deleting the Blob is
immediate; the next read-after-write from the gateway will
see the new state.

## Credential format mistakes to avoid

- **Don't include the underscore in the keyId.** The
  keyId character set is `A-Za-z0-9-`. If you set a keyId of
  `consumer_prod` and the random secret happens to start
  with `B` followed by more characters, the credential is
  `tpr_consumer_prod_Bxxx` and the gateway will interpret it
  as `keyId=consumer` and `randomSecret=prod_Bxxx` — neither
  the keyId nor the random secret you intended.
- **Don't add `sha256:` to the stored HMAC.** The stored
  value is the raw hex digest, no prefix. The comparison is
  hex-bytes-to-hex-bytes. A `sha256:abcdef…` value will not
  match the gateway's recomputation.
- **Don't wrap the HMAC in a second SHA-256.** The amendment
  is explicit: store the HMAC-SHA256 output directly, period.
- **Don't log the credential.** The Netlify function logs
  do not record the `Authorization` header. If you add custom
  logging, redact the credential.
- **Don't use the consumer client to store the credential
  on disk.** The client is designed to NOT persist the
  credential; that's the right default. If you need to
  persist it, use a secret manager.

## Pepper rotation

The pepper (`THREATPULSE_CREDENTIAL_PEPPER`) is a single
secret. Rotating it invalidates **every** existing
credential. Do this only in an emergency, or with a planned
overlap:

1. Issue new credentials under the new pepper (and a new
   keyId suffix like `-pepper-2026q4`).
2. Write the new credentials' HMACs to the Blob store.
3. Switch the consumer to the new credentials.
4. Wait for the consumer to confirm it's using the new
   credentials.
5. Set the new pepper on the gateway and restart the
   function.
6. Delete the old credentials' HMACs from the Blob store.

A pepper rotation without a planned overlap is an outage.
Plan it like a database password rotation.

## What the gateway does NOT do

- It does NOT rate-limit per-credential. The function's
  `rateLimit` config is per-IP and per-domain, not per
  credential. Per-credential hard quotas are deferred until
  an atomic counter store exists.
- It does NOT log the keyId. The keyId is an identifier; the
  request log records the route and the response code, not
  who made the request. If you need per-keyId audit logs,
  add a logger explicitly and document it.
- It does NOT support credential delegation, impersonation,
  or scopes. Every valid credential can read every manifest
  and every shard. Multi-tenant scoping is a future-version
  concern.
- It does NOT auto-expire credentials. A credential is
  valid until the Blob is deleted. The gateway reads
  `createdAt` from the store record (if present) for
  operator-side audit only; it does not enforce an expiry.

## Operational checklist

When you issue a credential, verify:

- [ ] The keyId matches `^[A-Za-z0-9-]{1,64}$`.
- [ ] The random secret is 32 bytes (43 base64url chars).
- [ ] The pepper matches the gateway's
      `THREATPULSE_CREDENTIAL_PEPPER` env var exactly.
- [ ] The stored HMAC is the lowercase hex digest, no
      `sha256:` prefix, no extra wrapping.
- [ ] A test request to the gateway returns 200 OK.

When you rotate a credential:

- [ ] New credential issued and stored.
- [ ] Consumer switched to the new credential.
- [ ] Old credential's Blob deleted.
- [ ] Old random secret discarded.

When you revoke a credential:

- [ ] The `credentials/<keyId>` Blob is deleted.
- [ ] The next request with the old credential returns 401.
- [ ] The random secret is discarded (it is no longer useful
      because the HMAC cannot be re-derived without the
      pepper).
