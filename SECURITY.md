# ThreatPulse Radar — Security Policy

This document is the public security policy for ThreatPulse
Radar. It covers the supported versions, the responsible
disclosure process, the out-of-scope categories and the
operator's contact channels.

## Supported versions

| Version | Status | Notes |
| --- | --- | --- |
| V6.8 (current) | Supported | The current production release. Security updates are issued on this line. |
| V6.7 | Supported | The previous release line. Security updates are issued on this line for at least 6 months after V6.8. |
| V6.6 and earlier | End-of-life | Not eligible for new security updates. Operators on these versions are encouraged to upgrade. |

## Reporting a vulnerability

If you have discovered a security vulnerability in
ThreatPulse Radar, please report it privately to the
operator. **Do not** open a public GitHub issue for a
security-sensitive report.

The operator's contact channels are documented in
`https://threatpulse.namanp.de/.well-known/security.txt`
per RFC 9116.

A high-quality report includes:

- A clear description of the issue and its impact.
- A reproducer (curl, browser steps, or a minimal
  test case).
- The affected version (commit SHA or release tag).
- Whether the issue is already known to you.
- Your contact details and a preferred disclosure
  timeline.

The operator commits to:

- An acknowledgement within 5 business days.
- A status update every 14 days until the issue is
  resolved.
- Coordinated public disclosure with a credit to the
  reporter unless the reporter requests anonymity.

## Out-of-scope

The following categories are intentionally out of scope
for this security policy:

- Issues that require the visitor to disable the
  browser's same-origin policy (e.g. by pasting
  arbitrary JavaScript into the devtools console while
  the dashboard is loaded).
- Issues that require the visitor to install a malicious
  browser extension.
- Issues that require physical access to a Hostinger
  data-centre machine.
- Theoretical attacks that require a hostile network
  operator to actively MITM a TLS connection
  (HSTS-preload and certificate-pinning are out of
  scope; the V6.9 milestone ships a conservative
  HSTS baseline that is a deliberate, documented
  trade-off).
- Missing security headers on third-party resources
  (the dashboard does not load any third-party
  resources, so this is not applicable).
- The `Proxy: Netlify` historical label (the V6.8
  closure branch removed the legacy label; the V6.9
  verification suite asserts the label is absent).

## Production security posture (V6.9)

The current production build applies:

- A conservative Content-Security-Policy with no
  `unsafe-eval`, no `unsafe-inline`, no wildcard
  origins, and only the documented same-origin
  `worker-src 'self' blob:` exception.
- `X-Frame-Options: DENY` and the equivalent
  `frame-ancestors 'none'` CSP directive.
- `Referrer-Policy: strict-origin-when-cross-origin`.
- A `Permissions-Policy` that denies every browser
  capability the dashboard does not actively use.
- `Strict-Transport-Security: max-age=31536000` with
  no `includeSubDomains` and no `preload`.
- `Cross-Origin-Resource-Policy: same-origin` for
  every non-dataset public route.
- A CORS policy that is open for the public dataset
  endpoint and same-origin for every other public
  surface.
- Bounded Node `headersTimeout`, `requestTimeout`,
  `keepAliveTimeout` and `maxRequestsPerConnection`
  on the Hostinger runtime.

The full audit and decision record is in
`docs/v6-9-privacy-cookie-and-security-hardening.md`.
The machine-readable verification is in
`scripts/verify-v69-privacy-and-runtime-hardening.mjs`.

## Operator contact

<!-- OPERATOR: replace the placeholder values below with the
real contact details for the production deployment. The
`security.txt` in `public/.well-known/security.txt` MUST
contain the same contact. -->

- Contact: `security@<OPERATOR-DOMAIN>`
- Encryption: PGP key fingerprint (optional):
  `<OPERATOR-PGP-FINGERPRINT>`
- Preferred language: English
- Acknowledgement SLA: 5 business days
