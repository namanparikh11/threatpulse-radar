/**
 * v5.7 — Filtered CSV export.
 *
 * Generates a single CSV file in the browser from the
 * currently-filtered vulnerability set. The export is
 * intentionally client-side only — no network call, no
 * server-side aggregation, no analytics — because a
 * filtered export of a defensive dashboard is a
 * single-user triage artifact, not a shared API.
 *
 * Spec contract:
 *   - Header row uses the documented column names exactly.
 *   - Every cell value is CSV-quoted (CR / LF / comma /
 *     leading-equals-plus-minus-at → quoted) so spreadsheet
 *     apps parse the file cleanly.
 *   - Cells that begin with `=`, `+`, `-`, or `@` are
 *     prefixed with a single quote to defeat formula
 *     injection. A CVE summary like "=cmd|'/c calc'!A1"
 *     becomes "'=cmd|'/c calc'!A1" — Excel / Sheets still
 *     render the cell as text.
 *   - The package-remediation fields (ecosystem / name /
 *     vulnerable range / first patched version) are
 *     collapsed into a single column per field with a
 *     documented separator so the CSV stays flat and
 *     spreadsheet-friendly. The separator is `; ` (semicolon
 *     + space) — it never appears inside a GitHub package
 *     name, ecosystem, or semver range, and the documented
 *     separator is part of the public contract.
 *   - No internal metadata, raw provider errors, cache
 *     markers, blob keys, tokens, or stack traces are
 *     exported. Only the documented columns appear.
 *   - The default filename embeds the current local date
 *     so a defender can keep multiple exports distinct.
 */

import type {
  GithubAdvisory,
  GithubAdvisoryPackage,
  SsvcAutomatable,
  SsvcExploitation,
  SsvcTechnicalImpact,
  Vulnerability,
} from '../types/vulnerability';
import { formatDate } from './format';

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

/**
 * Cells whose first character is one of these get a
 * leading single quote to prevent spreadsheet formula
 * injection. The set is the OWASP CSV-injection baseline.
 */
const FORMULA_TRIGGERS = new Set(['=', '+', '-', '@']);

/**
 * Separator used to join multiple GitHub-advisory package
 * entries inside a single CSV column. Documented as part
 * of the public contract — downstream consumers can split
 * the column on this exact string.
 */
export const PACKAGE_FIELD_SEPARATOR = '; ';

/**
 * The exact column header order. Adding / removing columns
 * is a breaking change for any downstream consumer.
 */
export const CSV_COLUMNS = [
  'CVE ID',
  'Summary',
  'Severity',
  'CVSS',
  'EPSS probability',
  'KEV',
  'Vendor',
  'Product',
  'Published date',
  'Recommended defensive action',
  'SSVC exploitation',
  'SSVC automatable',
  'SSVC technical impact',
  'GHSA ID',
  'Advisory severity',
  'Package ecosystems/names',
  'Vulnerable ranges',
  'First patched versions',
  'CISA KEV URL',
  'NVD URL',
  'GitHub Advisory URL',
] as const;

export type CsvColumn = (typeof CSV_COLUMNS)[number];

/* ------------------------------------------------------------------ */
/* Single-cell escaping                                               */
/* ------------------------------------------------------------------ */

/**
 * Escape a single CSV cell so that:
 *   1. Spreadsheet apps can't interpret a leading `=` / `+`
 *      / `-` / `@` as a formula.
 *   2. Embedded CR / LF / quote / comma are correctly quoted.
 *
 * The function returns the empty string for `null` /
 * `undefined` so an absent field never produces a stray
 * ", ," gap in the row.
 */
export function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  // Booleans render as "true" / "false" — explicit so a
  // spreadsheet doesn't interpret `false` as the number 0.
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  // Numbers render as-is. The CSV format does not require
  // quoting for pure digits, but the leading-character check
  // below is a no-op for digits anyway.
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return '';
    return String(value);
  }
  // Everything else (string, etc.) is coerced to string.
  let str = typeof value === 'string' ? value : String(value);
  // Defeat formula injection. A leading single quote is
  // interpreted by Excel / Sheets / Numbers as a literal
  // text marker and stripped on display. The original
  // character is preserved in the cell so a downstream
  // parser can still see the literal `=SUM(...)` content.
  if (str.length > 0 && FORMULA_TRIGGERS.has(str[0])) {
    str = "'" + str;
  }
  // Quote the cell if it contains a delimiter / line break /
  // double-quote, and escape any embedded double-quotes.
  if (
    str.includes(',') ||
    str.includes('"') ||
    str.includes('\n') ||
    str.includes('\r')
  ) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

/* ------------------------------------------------------------------ */
/* Per-vulnerability field formatters                                 */
/* ------------------------------------------------------------------ */

function joinPackageField(
  packages: GithubAdvisoryPackage[] | undefined,
  pick: (p: GithubAdvisoryPackage) => string
): string {
  if (!Array.isArray(packages) || packages.length === 0) return '';
  return packages
    .map((p) => pick(p))
    .filter((s) => s.length > 0)
    .join(PACKAGE_FIELD_SEPARATOR);
}

function findLink(v: Vulnerability, label: string): string {
  if (!Array.isArray(v.externalLinks)) return '';
  const hit = v.externalLinks.find(
    (l) => typeof l?.label === 'string' && l.label === label
  );
  return hit && typeof hit.url === 'string' ? hit.url : '';
}

function advisoryField(advisory: GithubAdvisory | undefined, pick: (a: GithubAdvisory) => string): string {
  if (!advisory) return '';
  return pick(advisory);
}

/**
 * Build a single CSV row (array of cell strings) for a
 * vulnerability record. The cell order matches
 * `CSV_COLUMNS` exactly.
 *
 * The function never mutates the input record. It is safe
 * to call repeatedly with the same input.
 */
export function buildCsvRow(v: Vulnerability): string[] {
  const advisory = v.githubAdvisory;
  return [
    escapeCsvCell(v.cveId),
    escapeCsvCell(v.summary),
    escapeCsvCell(v.severity),
    escapeCsvCell(v.cvssScore),
    escapeCsvCell(v.epssProbability),
    escapeCsvCell(v.kev),
    escapeCsvCell(v.vendor),
    escapeCsvCell(v.product),
    escapeCsvCell(formatDate(v.publishedDate)),
    escapeCsvCell(v.recommendedAction),
    escapeCsvCell(v.ssvcExploitation as SsvcExploitation | undefined),
    escapeCsvCell(v.ssvcAutomatable as SsvcAutomatable | undefined),
    escapeCsvCell(v.ssvcTechnicalImpact as SsvcTechnicalImpact | undefined),
    escapeCsvCell(advisoryField(advisory, (a) => a.ghsaId)),
    escapeCsvCell(advisoryField(advisory, (a) => a.advisorySeverity)),
    escapeCsvCell(
      joinPackageField(advisory?.packages, (p) =>
        [p.ecosystem, p.name].filter(Boolean).join('/')
      )
    ),
    escapeCsvCell(joinPackageField(advisory?.packages, (p) => p.vulnerableVersionRange)),
    escapeCsvCell(
      joinPackageField(advisory?.packages, (p) =>
        p.firstPatchedVersion === null ? '' : p.firstPatchedVersion
      )
    ),
    escapeCsvCell(findLink(v, 'CISA KEV')),
    escapeCsvCell(findLink(v, 'NVD')),
    escapeCsvCell(advisoryField(advisory, (a) => a.advisoryUrl)),
  ];
}

/* ------------------------------------------------------------------ */
/* Whole-file assembly                                                */
/* ------------------------------------------------------------------ */

/**
 * Build the full CSV body (header + rows) for a filtered
 * vulnerability list. Returns an empty string when the
 * list is empty so the caller can short-circuit the
 * download. Uses CRLF line endings — the documented
 * default for RFC 4180 — and a UTF-8 BOM prefix so Excel
 * reads non-ASCII characters correctly.
 */
export function toCsv(rows: Vulnerability[]): string {
  if (rows.length === 0) return '';
  const lines: string[] = [];
  lines.push(CSV_COLUMNS.map(escapeCsvCell).join(','));
  for (const v of rows) {
    lines.push(buildCsvRow(v).join(','));
  }
  // \uFEFF is the UTF-8 BOM. Excel needs it to read
  // non-ASCII characters correctly; other spreadsheet apps
  // ignore it. The BOM is part of the public contract.
  return '\uFEFF' + lines.join('\r\n') + '\r\n';
}

/**
 * Default export filename. Embeds the current local date
 * (YYYY-MM-DD) so a defender can keep multiple exports
 * distinct. The `.csv` extension is required for
 * spreadsheet-app double-click handling.
 */
export function defaultExportFilename(now: Date = new Date()): string {
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  return `threatpulse-radar-${yyyy}-${mm}-${dd}.csv`;
}

/**
 * Trigger a browser download for a generated CSV body.
 *
 * Uses a Blob + object URL + temporary anchor click — the
 * standard "download in the browser" pattern. The object
 * URL is revoked on the next tick so the browser doesn't
 * keep a reference alive after the click handler returns.
 *
 * The function is a no-op when the body is empty (the
 * caller is expected to disable the button in that case,
 * but the guard is here as a second line of defense).
 *
 * The function is only safe to call in a browser
 * environment. Server-side use would need a different
 * transport. The dashboard never calls it server-side.
 */
export function downloadCsv(
  filename: string,
  body: string
): void {
  if (typeof document === 'undefined') return;
  if (body.length === 0) return;
  const blob = new Blob([body], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener noreferrer';
  // Some browsers require the anchor to be in the DOM
  // before .click() will trigger a download.
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Defer revocation so the browser has time to start the
  // download. Revoking too early cancels the download in
  // some browsers.
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}
