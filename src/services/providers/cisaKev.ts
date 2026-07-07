/**
 * CISA Known Exploited Vulnerabilities (KEV) catalog — live provider.
 *
 * Endpoint:
 *   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *
 * CISA serves the feed with `Access-Control-Allow-Origin: *`, so a
 * browser can `fetch()` it directly. We abort after a short timeout
 * so a slow / blocked CISA response doesn't hang the dashboard —
 * the caller (vulnerabilityService) catches the error and falls back
 * to the local mock dataset.
 *
 * Normalization rules:
 *   - cveID                       -> id, cveId
 *   - vendorProject / product     -> vendor, product
 *   - vulnerabilityName           -> summary
 *   - shortDescription            -> description (with a note about
 *                                   missing CVSS / EPSS so the UI can
 *                                   render the data honestly)
 *   - requiredAction              -> recommendedAction
 *   - dateAdded                   -> publishedDate (fallback: today)
 *   - kev                         -> always `true` here, by definition
 *   - severity                    -> 'Critical' if
 *                                   knownRansomwareCampaignUse ===
 *                                   'Known', else 'High' (KEV is by
 *                                   construction at least High)
 *   - cvssScore / epssProbability -> 0 (not provided by CISA; we don't
 *                                   fabricate values)
 *   - source                      -> 'CISA KEV'
 */
import type {
  Severity,
  Vulnerability,
  VulnerabilitySource,
} from '../../types/vulnerability';

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const FETCH_TIMEOUT_MS = 8_000;

/** Shape of one record inside the CISA KEV feed's `vulnerabilities` array. */
interface CisaKevRecord {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes?: string;
  cwes?: string[];
}

/** Top-level shape of the CISA KEV feed (only the fields we read). */
interface CisaKevFeed {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: CisaKevRecord[];
}

/**
 * Fetch the live CISA KEV catalog and normalize every record into
 * our `Vulnerability` shape. Throws on network error, abort, non-2xx,
 * or shape mismatch — the caller decides what to do (fall back to
 * mock, surface an error, etc.).
 */
export async function fetchCisaKev(): Promise<Vulnerability[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(CISA_KEV_URL, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      // Don't cache; CISA updates the feed and we always want the
      // latest on page load. The browser may still cache via its
      // own heuristics; that's harmless — worst case the user is
      // 5 minutes behind on a fresh page load.
      cache: 'no-store',
    });
    if (!response.ok) {
      throw new Error(
        `CISA KEV fetch failed: HTTP ${response.status} ${response.statusText}`
      );
    }
    const feed = (await response.json()) as CisaKevFeed;
    if (!feed || !Array.isArray(feed.vulnerabilities)) {
      throw new Error('CISA KEV feed has unexpected shape (no vulnerabilities array)');
    }
    return feed.vulnerabilities
      .filter((rec): rec is CisaKevRecord => Boolean(rec && rec.cveID))
      .map(normalizeCisaKevRecord);
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------ */
/* Normalization                                                      */
/* ------------------------------------------------------------------ */

/**
 * Pick a sensible severity for a CISA KEV record. CISA does not
 * include CVSS, so we use the only signal they do give us:
 *   - `knownRansomwareCampaignUse === 'Known'`  -> Critical
 *   - everything else (still actively exploited) -> High
 *
 * KEV-by-construction means at least High is honest; if a record
 * has CVSS < 7.0 (rare, but possible) we'd technically be
 * over-stating. The fix in v3 is to backfill CVSS from NVD.
 */
function severityForCisaKev(rec: CisaKevRecord): Severity {
  if (rec.knownRansomwareCampaignUse === 'Known') return 'Critical';
  return 'High';
}

function safeDate(iso: string | undefined): string {
  if (!iso) return new Date().toISOString().slice(0, 10);
  // CISA ships `YYYY-MM-DD` already; pass through if it parses.
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
  return d.toISOString().slice(0, 10);
}

export function normalizeCisaKevRecord(rec: CisaKevRecord): Vulnerability {
  const cveId = rec.cveID.trim();
  const short = (rec.shortDescription ?? '').trim();
  const name = (rec.vulnerabilityName ?? '').trim();
  const source: VulnerabilitySource = 'CISA KEV';

  return {
    // Stable id. KEV records are unique by cveID, so this is safe.
    id: `kev-${cveId.toLowerCase()}`,
    cveId,
    // Prefer the named vulnerability; fall back to the description.
    summary: name || short || cveId,
    // Be transparent in the description that CVSS / EPSS are not
    // provided by the CISA feed — the user can see why the cells
    // are 0.0 in the table.
    description:
      short +
      (short ? ' ' : '') +
      '(CVSS and EPSS scores are not provided by the CISA KEV feed; ' +
      'they are populated when NVD / FIRST EPSS are wired in.)',
    severity: severityForCisaKev(rec),
    cvssScore: 0,
    epssProbability: 0,
    kev: true,
    vendor: (rec.vendorProject ?? '').trim() || 'Unknown',
    product: (rec.product ?? '').trim() || 'Unknown',
    publishedDate: safeDate(rec.dateAdded),
    source,
    recommendedAction:
      (rec.requiredAction ?? '').trim() ||
      'Apply vendor patch per CISA KEV guidance.',
    externalLinks: [
      {
        label: 'CISA KEV',
        url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog/search?query=${encodeURIComponent(cveId)}`,
      },
      {
        label: 'NVD',
        url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
      },
    ],
  };
}
