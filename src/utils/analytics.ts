/**
 * Pure filtering / sorting / aggregation helpers for vulnerabilities.
 *
 * Pipeline overview:
 *   1. applyFilters(all, filters)    -> narrowed list
 *   2. applySortBy(narrowed, sort)   -> ordered list
 *
 * Filtering combines 4 independent predicates (severity, KEV, EPSS, search).
 * They are AND-ed together so all conditions must match.
 *
 * The search predicate is case-insensitive, trims whitespace, and matches
 * across: cveId, summary, description, vendor, product, severity, source.
 */
import type {
  DashboardStats,
  Severity,
  SortDirection,
  SortField,
  SortState,
  Vulnerability,
  VulnerabilityFilters,
} from '../types/vulnerability';
import { SEVERITY_ORDER } from './severity';

/** Critical -> 0, High -> 1, Medium -> 2, Low -> 3 (lower = "more severe") */
const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

/**
 * Normalize a free-text search query.
 * - trims surrounding whitespace
 * - lower-cases the whole string
 * - collapses inner whitespace to a single space
 */
export function normalizeQuery(raw: string): string {
  return raw.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Build the lowercase "haystack" we search against.
 * Includes the title (summary) for natural phrasing matches like
 * "fortinet" or "auth bypass".
 */
function buildHaystack(v: Vulnerability): string {
  return [
    v.cveId,
    v.summary,
    v.description,
    v.vendor,
    v.product,
    v.severity,
    v.source,
  ]
    .join(' ')
    .toLowerCase();
}

/**
 * Apply all active filters to a vulnerability list.
 * Pure function — never mutates the input.
 */
export function applyFilters(
  vulns: Vulnerability[],
  filters: VulnerabilityFilters
): Vulnerability[] {
  const q = normalizeQuery(filters.search);

  return vulns.filter((v) => {
    // Severity filter (All passes everything)
    if (filters.severity !== 'All' && v.severity !== filters.severity) {
      return false;
    }
    // KEV-only toggle
    if (filters.kevOnly && !v.kev) {
      return false;
    }
    // Minimum EPSS — half-open [minEpss, 1.0]
    if (v.epssProbability < filters.minEpss) {
      return false;
    }
    // Text search (only when non-empty after normalization)
    if (q.length > 0) {
      const haystack = buildHaystack(v);
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

/**
 * Stable, deterministic comparator for a single sort field.
 * Returns a number whose sign indicates ordering BEFORE direction is applied.
 */
function compareByField(a: Vulnerability, b: Vulnerability, field: SortField): number {
  switch (field) {
    case 'newest':
    case 'publishedDate':
      // ISO date strings are lexicographically comparable.
      return a.publishedDate.localeCompare(b.publishedDate);
    case 'cvss':
      return a.cvssScore - b.cvssScore;
    case 'epss':
      return a.epssProbability - b.epssProbability;
    case 'severity':
      // Natural order is "most severe first" (Critical, High, Medium, Low);
      // the `direction` factor in `applySortBy` flips it for ascending.
      return (SEVERITY_RANK[b.severity] ?? 99) - (SEVERITY_RANK[a.severity] ?? 99);
    case 'kev':
      return (a.kev ? 1 : 0) - (b.kev ? 1 : 0);
    case 'vendor':
      return a.vendor.localeCompare(b.vendor);
  }
}

/**
 * Sort a list of vulnerabilities by a (field, direction) pair.
 * Ties are broken by publishedDate desc + cveId asc for a stable look.
 */
export function applySortBy(
  vulns: Vulnerability[],
  sort: SortState
): Vulnerability[] {
  const dir: SortDirection = sort.direction;
  const factor = dir === 'asc' ? 1 : -1;
  const copy = [...vulns];

  copy.sort((a, b) => {
    const primary = compareByField(a, b, sort.field) * factor;
    if (primary !== 0) return primary;
    // Tiebreaker: newest first, then CVE id ascending.
    const dateCmp = b.publishedDate.localeCompare(a.publishedDate);
    if (dateCmp !== 0) return dateCmp;
    return a.cveId.localeCompare(b.cveId);
  });

  return copy;
}

/* ------------------------------------------------------------------ */
/* Aggregations (unchanged shape, kept here for one-stop analytics)    */
/* ------------------------------------------------------------------ */

export function computeStats(
  vulns: Vulnerability[],
  now: Date = new Date()
): DashboardStats {
  const total = vulns.length;
  const critical = vulns.filter((v) => v.severity === 'Critical').length;
  const high = vulns.filter((v) => v.severity === 'High').length;
  const knownExploited = vulns.filter((v) => v.kev).length;
  const averageEpss =
    total === 0
      ? 0
      : vulns.reduce((acc, v) => acc + v.epssProbability, 0) / total;
  const sevenDaysMs = 1000 * 60 * 60 * 24 * 7;
  const newThisWeek = vulns.filter((v) => {
    const t = new Date(v.publishedDate).getTime();
    return now.getTime() - t <= sevenDaysMs;
  }).length;
  return { total, critical, high, knownExploited, averageEpss, newThisWeek };
}

export function countBySeverity(vulns: Vulnerability[]): Record<Severity, number> {
  const init: Record<Severity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };
  for (const v of vulns) init[v.severity] += 1;
  return init;
}

/** Bucket EPSS probabilities into low / medium / high / critical risk ranges. */
export function countByEpssBucket(vulns: Vulnerability[]) {
  const buckets = [
    { name: '0-10%',   min: 0,    max: 0.10, count: 0 },
    { name: '10-30%',  min: 0.10, max: 0.30, count: 0 },
    { name: '30-60%',  min: 0.30, max: 0.60, count: 0 },
    { name: '60-100%', min: 0.60, max: 1.01, count: 0 },
  ];
  for (const v of vulns) {
    const b = buckets.find(
      (x) => v.epssProbability >= x.min && v.epssProbability < x.max
    );
    if (b) b.count += 1;
  }
  return buckets;
}

export function countByDay(
  vulns: Vulnerability[],
  days: number = 14,
  now: Date = new Date()
): { date: string; count: number }[] {
  const result: { date: string; count: number; key: string }[] = [];
  const dayMs = 1000 * 60 * 60 * 24;
  for (let i = days - 1; i >= 0; i -= 1) {
    const day = new Date(now.getTime() - i * dayMs);
    const key = day.toISOString().slice(0, 10);
    result.push({
      date: day.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
      count: 0,
      key,
    });
  }
  for (const v of vulns) {
    const dKey = v.publishedDate.slice(0, 10);
    const entry = result.find((r) => r.key === dKey);
    if (entry) entry.count += 1;
  }
  // Strip the helper key before returning.
  return result.map(({ date, count }) => ({ date, count }));
}

export function severityOrderIndex(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}
