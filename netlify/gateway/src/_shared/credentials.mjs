/**
 * V6.0 — Credential format, generation, and verification.
 *
 * Per the V6.0 amendment #6:
 *   - Credential format: tpr_<keyId>_<randomSecret>
 *   - keyId is a safe unambiguous character set
 *   - Store the HMAC-SHA256 output directly; do not wrap it in a
 *     second SHA-256
 *   - HMAC formula:
 *       HMAC-SHA256(THREATPULSE_CREDENTIAL_PEPPER, keyId + ":" + randomSecret)
 *   - Constant-time digest comparison
 *   - Because keyId is in the credential, do not maintain a
 *     mutable credentials-index Blob; read credentials/{keyId}
 *     directly
 *
 * The credential never carries any privileged information. The
 * keyId identifies the key (so the gateway can look up the
 * stored HMAC); the randomSecret is the secret half. The
 * THREATPULSE_CREDENTIAL_PEPPER is a server-side salt that
 * prevents an attacker with read access to the Blob store from
 * using the stored HMAC directly — they would also need the
 * pepper, which lives only in the gateway's environment.
 *
 * Storage layout in the tpr-baseline store:
 *   credentials/{keyId}  →  { hmac: "<hex>", createdAt: ISO, label?: string }
 *
 * The stored value is the hex digest (no `sha256:` prefix), per
 * the amendment.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** Prefix that marks a V6.0 ThreatPulse Radar credential. */
export const CREDENTIAL_PREFIX = 'tpr_';

/** Maximum keyId length. The character set is `A-Za-z0-9-` —
 *  alphanumeric and dash. We deliberately exclude `_` because
 *  the random secret is base64url-encoded (which uses `_`), and
 *  `_` is also the separator between the keyId and the random
 *  secret in the credential string. An unambiguous keyId
 *  character set is required to parse the credential back into
 *  its two halves. */
export const KEY_ID_MAX_LENGTH = 64;

/** Regex for the keyId character set (safe, unambiguous). */
export const KEY_ID_PATTERN = /^[A-Za-z0-9-]{1,64}$/;

/** Length (in bytes) of the random secret. 32 bytes = 256 bits. */
export const RANDOM_SECRET_BYTES = 32;

/** Env var for the server-side pepper. */
export const PEPPER_ENV_VAR = 'THREATPULSE_CREDENTIAL_PEPPER';

/** Blob key for a credential's stored HMAC. */
export function credentialBlobKey(keyId) {
  if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
    throw new Error('credentialBlobKey: keyId must match ' + KEY_ID_PATTERN);
  }
  return `credentials/${keyId}`;
}

/**
 * Parse a credential string of the form `tpr_<keyId>_<randomSecret>`.
 * Returns `{ keyId, randomSecret }` on success, or null on any
 * parse error (wrong prefix, wrong shape, illegal characters).
 */
export function parseCredential(credential) {
  if (typeof credential !== 'string') return null;
  if (!credential.startsWith(CREDENTIAL_PREFIX)) return null;
  const rest = credential.slice(CREDENTIAL_PREFIX.length);
  // The first underscore in `rest` separates keyId from randomSecret.
  // keyId is restricted to KEY_ID_PATTERN which does not include
  // underscores; the randomSecret is base64url (no underscores) so
  // the first underscore in `rest` IS the separator.
  const sep = rest.indexOf('_');
  if (sep <= 0) return null;
  const keyId = rest.slice(0, sep);
  const randomSecret = rest.slice(sep + 1);
  if (randomSecret.length === 0) return null;
  if (!KEY_ID_PATTERN.test(keyId)) return null;
  if (randomSecret.length < 16) return null; // sanity: short secrets are nonsense
  return { keyId, randomSecret };
}

/**
 * Compute the HMAC-SHA256 of `keyId + ":" + randomSecret` using
 * the pepper. Returns the lowercase hex digest with NO prefix.
 */
export function computeHmac({ pepper, keyId, randomSecret }) {
  if (typeof pepper !== 'string' || pepper.length === 0) {
    throw new Error('computeHmac: pepper is required');
  }
  if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
    throw new Error('computeHmac: keyId is invalid');
  }
  if (typeof randomSecret !== 'string' || randomSecret.length === 0) {
    throw new Error('computeHmac: randomSecret is required');
  }
  const h = createHmac('sha256', pepper);
  h.update(`${keyId}:${randomSecret}`);
  return h.digest('hex');
}

/**
 * Constant-time comparison of two hex digests. Returns true iff
 * they are equal.
 *
 * The comparison decodes both hex strings to bytes and uses
 * crypto.timingSafeEqual. Both inputs must be the same length
 * (a hex digest is always the same length); the length check
 * happens before the constant-time comparison so a wrong-length
 * input is rejected without leaking a per-byte timing channel.
 */
export function constantTimeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  // Both hex strings must be the same length as a SHA-256 digest
  // (64 hex chars) for the comparison to be well-defined.
  if (a.length !== 64) return false;
  // Both must be valid hex.
  if (!/^[0-9a-fA-F]+$/.test(a) || !/^[0-9a-fA-F]+$/.test(b)) return false;
  // The buffer comparison is constant-time over the whole buffer.
  return timingSafeEqual(Buffer.from(a.toLowerCase(), 'hex'), Buffer.from(b.toLowerCase(), 'hex'));
}

/**
 * Generate a new credential. Returns:
 *   {
 *     credential:    "tpr_<keyId>_<randomSecret>",
 *     keyId:         <string>,
 *     randomSecret:  <string>,
 *     hmac:          <hex digest — what to store in credentials/{keyId}>,
 *   }
 *
 * The caller is expected to write `hmac` to the Blob store at
 * `credentials/{keyId}`. The `randomSecret` is returned in
 * plaintext so the operator can hand it to the consumer; the
 * gateway never needs it after the HMAC is stored.
 */
export function generateCredential({ pepper, keyId, randomBytesImpl = randomBytes } = {}) {
  if (typeof pepper !== 'string' || pepper.length === 0) {
    throw new Error('generateCredential: pepper is required');
  }
  const finalKeyId = (typeof keyId === 'string' && keyId.length > 0)
    ? keyId
    : randomKeyId(randomBytesImpl);
  if (!KEY_ID_PATTERN.test(finalKeyId)) {
    throw new Error('generateCredential: keyId does not match the safe character set');
  }
  const randomSecret = randomBytesImpl(RANDOM_SECRET_BYTES).toString('base64url');
  const hmac = computeHmac({ pepper, keyId: finalKeyId, randomSecret });
  return {
    credential: `${CREDENTIAL_PREFIX}${finalKeyId}_${randomSecret}`,
    keyId: finalKeyId,
    randomSecret,
    hmac,
  };
}

/**
 * Generate a random keyId from the safe character set. The
 * default length is 16 characters, which gives ~95 bits of
 * entropy against a 64-character alphabet — well above the
 * collision probability we care about.
 */
export function randomKeyId(randomBytesImpl = randomBytes) {
  // Note: the alphabet deliberately does NOT include `_`. See
  // KEY_ID_PATTERN for the rationale (the underscore is the
  // separator in the credential string, and the random secret
  // is base64url which uses `_`).
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';
  const bytes = randomBytesImpl(16);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return out;
}

/**
 * Verify a credential against a stored HMAC. Returns:
 *   { valid: true,  keyId }  on success
 *   { valid: false, reason }  on any failure
 *
 * The reason is one of: 'malformed', 'unknown-key', 'malformed-store-record',
 * 'hmac-mismatch'. Callers should NOT expose the reason to the
 * client (a 401 with a generic message is sufficient); the reason
 * is for server-side logging.
 *
 * @param {Object} args
 * @param {string} args.credential    - the full credential string
 * @param {string} args.pepper        - the server-side pepper
 * @param {Object} args.storeRecord   - the parsed JSON value of
 *                                      credentials/{keyId} (or null)
 * @returns {Object}
 */
export function verifyCredential({ credential, pepper, storeRecord }) {
  const parsed = parseCredential(credential);
  if (!parsed) return { valid: false, reason: 'malformed' };
  if (!storeRecord || typeof storeRecord !== 'object') {
    return { valid: false, reason: 'unknown-key' };
  }
  const storedHmac = storeRecord.hmac;
  if (typeof storedHmac !== 'string' || storedHmac.length === 0) {
    return { valid: false, reason: 'malformed-store-record' };
  }
  const computed = computeHmac({ pepper, keyId: parsed.keyId, randomSecret: parsed.randomSecret });
  if (!constantTimeHexEqual(storedHmac, computed)) {
    return { valid: false, reason: 'hmac-mismatch' };
  }
  return { valid: true, keyId: parsed.keyId };
}

/**
 * Pull the credential pepper from the environment. Returns null
 * if unset. The gateway must refuse all requests when the pepper
 * is not configured (fail closed).
 */
export function getPepperFromEnv(env = process.env) {
  const v = env && env[PEPPER_ENV_VAR];
  if (typeof v !== 'string' || v.length === 0) return null;
  return v;
}
