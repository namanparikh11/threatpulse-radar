/**
 * V6.5 — Report redaction.
 *
 * Redaction is applied BEFORE the checksum is
 * computed, so excluded values never enter the digest
 * input, the JSON, the HTML, the Markdown, the
 * preview, the comments, the attributes, the
 * filenames, or the metadata.
 *
 * Modes:
 *   - 'none'                 : no redaction
 *   - 'exclude-private-notes': omit the local `note`
 *   - 'exclude-local-tags'   : omit the local `tags`
 *   - 'exclude-all-user-text': omit BOTH notes and tags,
 *                                plus any user-authored
 *                                status / priority /
 *                                triage annotations
 *   - 'identifiers-only'     : the CVE id, the
 *                                public-side fields, the
 *                                provenance, and the
 *                                source-health summary
 *                                ONLY. No local
 *                                workspace, no
 *                                provider-facts narrative
 *                                beyond the identifier
 *                                block.
 *
 * The function is pure: same input + same mode →
 * same output.
 */

import { FIELD_KIND } from './schema.mjs';

/** True when the mode strips the workspace note. */
export function modeHidesNote(mode) {
  return mode === 'exclude-private-notes'
    || mode === 'exclude-all-user-text'
    || mode === 'identifiers-only';
}

/** True when the mode strips the workspace tags. */
export function modeHidesTags(mode) {
  return mode === 'exclude-local-tags'
    || mode === 'exclude-all-user-text'
    || mode === 'identifiers-only';
}

/** True when the mode strips the workspace status /
 *  priority fields. */
export function modeHidesStatus(mode) {
  return mode === 'exclude-all-user-text'
    || mode === 'identifiers-only';
}

/** True when the mode strips the per-CVE section
 *  body entirely (only the identifier list survives). */
export function modeHidesBody(mode) {
  return mode === 'identifiers-only';
}

/** Classify a value's provenance. The exporter and
 *  preview use this to render an inline
 *  "(provider fact)" / "(ThreatPulse-derived)" /
 *  "(user-authored)" label. */
export function fieldKindOf(path) {
  // Public-intelligence metadata is system-metadata.
  if (path === 'publicIntelligence' || path.startsWith('publicIntelligence.')) {
    return FIELD_KIND.SYSTEM_METADATA;
  }
  // Local workspace fields are user-authored.
  if (path === 'workspace' || path.startsWith('workspace.')) {
    return FIELD_KIND.USER_AUTHORED;
  }
  // Provider facts (CVE id, severity, CVSS, EPSS, KEV,
  // SSVC, vulnrichment, githubAdvisory, osv, withdrawn)
  // are provider-fact.
  if (path.startsWith('provider.')) return FIELD_KIND.PROVIDER_FACT;
  // ThreatPulse classifications (action-required,
  // changed-since-review) are threatpulse-derived.
  if (path.startsWith('derived.')) return FIELD_KIND.THREATPULSE_DERIVED;
  return FIELD_KIND.SYSTEM_METADATA;
}

/** Field-level metadata for the inline label renderer. */
export function describeField(path) {
  const kind = fieldKindOf(path);
  if (kind === FIELD_KIND.PROVIDER_FACT) return 'Provider fact';
  if (kind === FIELD_KIND.THREATPULSE_DERIVED) return 'ThreatPulse-derived';
  if (kind === FIELD_KIND.USER_AUTHORED) return 'User-authored local field';
  if (kind === FIELD_KIND.UNAVAILABLE) return 'Unavailable or uncertain';
  return 'System metadata';
}
