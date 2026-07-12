/**
 * v5.7 — Defender-view presets.
 *
 * Each preset is a deterministic, side-effect-free predicate
 * over a `Vulnerability` record. The presets are intentionally
 * implemented as pure data + pure functions so the UI can
 * render the selection rules verbatim and so the acceptance
 * suite can exercise them without a DOM.
 *
 * Design contract (per the v5.7 spec):
 *  - Preset criteria are EXPLICIT. Each preset carries a
 *    `criteria` array of human-readable lines that the UI
 *    shows next to the chip so a defender can read the
 *    rule without inferring it.
 *  - Presets use only fields already on the `Vulnerability`
 *    type. They do not invent, combine, or score — each rule
 *    inspects a single upstream field and is AND-ed.
 *  - A preset is NEVER the source of a hidden combined score.
 *    It is just a different filter against the same data the
 *    table already shows.
 *  - Absence of enrichment is never treated as a negative
 *    signal. Missing SSVC data means "unknown", not "no"; a
 *    missing GitHub Advisory means "no reviewed advisory",
 *    not "no fix exists".
 */

import type {
  GithubAdvisory,
  Vulnerability,
} from '../types/vulnerability';

/* ------------------------------------------------------------------ */
/* Public types                                                       */
/* ------------------------------------------------------------------ */

/**
 * Identifier for a defender-view preset. A null `presetId` in
 * the filter state means "no preset active — show all rows."
 */
export type PresetId =
  | 'exploited-and-patchable'
  | 'active-exploitation-context'
  | 'high-exploitation-likelihood'
  | 'patch-information-unavailable'
  | 'recently-added-kev';

export interface DefenderPreset {
  id: PresetId;
  /** Short label rendered on the chip. */
  label: string;
  /**
   * Single-sentence summary the chip shows on hover / aria-label.
   * Mirrors the user-facing copy in the v5.7 spec.
   */
  summary: string;
  /**
   * The explicit selection rule. Each line is a single
   * AND-ed predicate against a `Vulnerability` field. The UI
   * surfaces these lines so a defender can see what the
   * preset is actually filtering on.
   */
  criteria: string[];
  /** Pure predicate. */
  predicate: (v: Vulnerability) => boolean;
}

/* ------------------------------------------------------------------ */
/* Predicate helpers                                                  */
/* ------------------------------------------------------------------ */

/**
 * True if the record carries a positive reviewed GitHub
 * Advisory (i.e. `vuln.githubAdvisory?.ghsaId` is set).
 *
 * Absence is treated as `false` (no advisory), never as
 * "negative assessment" or "no fix exists."
 */
export function hasReviewedGithubAdvisory(v: Vulnerability): boolean {
  return !!(v.githubAdvisory && v.githubAdvisory.ghsaId);
}

/**
 * True if the reviewed advisory contains at least one
 * package entry with a non-null `firstPatchedVersion`.
 *
 * This is the "patchable" signal: we have a reviewed
 * advisory AND we have a concrete patched version for at
 * least one package.
 */
export function hasPatchablePackage(v: Vulnerability): boolean {
  const advisory: GithubAdvisory | undefined = v.githubAdvisory;
  if (!advisory || !Array.isArray(advisory.packages)) return false;
  return advisory.packages.some(
    (p) => typeof p.firstPatchedVersion === 'string' && p.firstPatchedVersion.length > 0
  );
}

/**
 * True if the reviewed advisory contains at least one
 * package entry with a null `firstPatchedVersion`.
 *
 * This is the "patch information unavailable" signal: we
 * have a reviewed advisory, but at least one of its
 * packages has no concrete patched version. The dashboard
 * never treats this as "no fix exists" — the field is
 * labeled "First patched version unavailable."
 */
export function hasPackageWithMissingPatchedVersion(v: Vulnerability): boolean {
  const advisory: GithubAdvisory | undefined = v.githubAdvisory;
  if (!advisory || !Array.isArray(advisory.packages)) return false;
  return advisory.packages.some((p) => p.firstPatchedVersion === null);
}

/**
 * True if every package entry on the reviewed advisory has
 * a null `firstPatchedVersion`. The "all packages
 * unavailable" flavour of the unavailable-patch preset.
 */
export function allPackagesMissingPatchedVersion(v: Vulnerability): boolean {
  const advisory: GithubAdvisory | undefined = v.githubAdvisory;
  if (!advisory || !Array.isArray(advisory.packages) || advisory.packages.length === 0) {
    return false;
  }
  return advisory.packages.every((p) => p.firstPatchedVersion === null);
}

/**
 * True if the record carries a CISA-ADP SSVC record whose
 * `ssvcExploitation` value is `active`.
 */
export function ssvcSaysActive(v: Vulnerability): boolean {
  return v.ssvcExploitation === 'active';
}

/**
 * True if the record carries any CISA-ADP SSVC record at
 * all (i.e. at least one of the three SSVC fields is
 * present). Absence means "no assessment available", not
 * "no exploitation."
 */
export function hasSsvcAssessment(v: Vulnerability): boolean {
  return (
    !!v.ssvcExploitation ||
    !!v.ssvcAutomatable ||
    !!v.ssvcTechnicalImpact
  );
}

/**
 * "Recently added KEV" — KEV-listed CVE with a
 * `publishedDate` within the last `windowDays` days.
 *
 * Note: the dashboard does not currently surface the CISA
 * KEV `dateAdded` field separately; the publishedDate is
 * the closest publicly available proxy. The preset label
 * makes the window explicit so a defender can read the
 * rule from the chip.
 */
export function isRecentKev(
  v: Vulnerability,
  now: Date,
  windowDays: number
): boolean {
  if (!v.kev) return false;
  if (typeof v.publishedDate !== 'string') return false;
  const t = Date.parse(v.publishedDate);
  if (Number.isNaN(t)) return false;
  const ageMs = now.getTime() - t;
  return ageMs >= 0 && ageMs <= windowDays * 24 * 60 * 60 * 1000;
}

/* ------------------------------------------------------------------ */
/* Preset definitions                                                 */
/* ------------------------------------------------------------------ */

/** EPSS threshold the "high exploitation likelihood" preset uses. */
export const HIGH_EPSS_THRESHOLD = 0.7;

/** KEV recency window (in days) the "recently added KEV" preset uses. */
export const RECENT_KEV_WINDOW_DAYS = 30;

export const PRESETS: DefenderPreset[] = [
  {
    id: 'exploited-and-patchable',
    label: 'Exploited and patchable',
    summary:
      'CISA KEV-listed with a concrete first patched version from a reviewed GitHub Advisory.',
    criteria: [
      'kev is true',
      'a reviewed GitHub Advisory exists',
      'at least one package has a non-null first patched version',
    ],
    predicate: (v) => v.kev && hasPatchablePackage(v),
  },
  {
    id: 'active-exploitation-context',
    label: 'Active exploitation context',
    summary:
      'CISA KEV-listed with a CISA Vulnrichment SSVC record flagging active exploitation.',
    criteria: [
      'kev is true',
      'CISA Vulnrichment SSVC exploitation is "active"',
    ],
    predicate: (v) => v.kev && ssvcSaysActive(v),
  },
  {
    id: 'high-exploitation-likelihood',
    label: 'High exploitation likelihood',
    summary:
      'FIRST EPSS probability at or above the documented threshold for high likelihood.',
    criteria: [
      `epssProbability >= ${HIGH_EPSS_THRESHOLD} (i.e. ≥ 70%)`,
    ],
    predicate: (v) => v.epssProbability >= HIGH_EPSS_THRESHOLD,
  },
  {
    id: 'patch-information-unavailable',
    label: 'Patch information unavailable',
    summary:
      'A reviewed GitHub Advisory exists but the upstream record does not list a first patched version for at least one affected package. Reported as unavailable information, never as "no fix exists."',
    criteria: [
      'a reviewed GitHub Advisory exists',
      'at least one affected package has no first patched version',
    ],
    predicate: (v) =>
      hasReviewedGithubAdvisory(v) &&
      hasPackageWithMissingPatchedVersion(v),
  },
  {
    id: 'recently-added-kev',
    label: 'Recently added KEV',
    summary:
      'CISA KEV-listed CVE published within the documented recency window.',
    criteria: [
      'kev is true',
      `publishedDate within the last ${RECENT_KEV_WINDOW_DAYS} days`,
    ],
    predicate: (v) => isRecentKev(v, new Date(), RECENT_KEV_WINDOW_DAYS),
  },
];

/* ------------------------------------------------------------------ */
/* Registry lookups                                                   */
/* ------------------------------------------------------------------ */

const PRESET_BY_ID = new Map<PresetId, DefenderPreset>(
  PRESETS.map((p) => [p.id, p] as const)
);

export function getPreset(id: PresetId | null): DefenderPreset | null {
  if (id === null) return null;
  return PRESET_BY_ID.get(id) ?? null;
}

/**
 * Apply a preset to a list. Returns the input list unchanged
 * when no preset is active. Pure — never mutates the input.
 */
export function applyPreset(
  vulns: Vulnerability[],
  presetId: PresetId | null,
  now: Date = new Date()
): Vulnerability[] {
  if (presetId === null) return vulns;
  const preset = getPreset(presetId);
  if (!preset) return vulns;
  // "Recently added KEV" needs `now` to evaluate recency. All
  // other predicates are pure on the record alone. We inject
  // `now` into the predicate's closure for the KEV preset at
  // preset-definition time so callers don't have to thread the
  // clock through every other preset.
  if (preset.id === 'recently-added-kev') {
    return vulns.filter((v) => isRecentKev(v, now, RECENT_KEV_WINDOW_DAYS));
  }
  return vulns.filter(preset.predicate);
}
