/**
 * V6.1 — Public source-health types.
 *
 * The Source Health panel reads the `sources` array from
 * the dataset endpoint's default-mode response. Each
 * source carries its derived state (computed at request
 * time from the persisted observations) and a
 * sanitized-attempt-warning tooltip. No env-var names
 * appear in any field.
 */

export type SourceAuthentication = 'none' | 'optional-server-side' | 'required-server-side';

export type SourceState = 'unknown' | 'fresh' | 'partial' | 'stale' | 'unavailable';

export type SourceType = 'gating' | 'enrichment' | 'incremental' | 'canonical';

export interface SourceStatus {
  id: 'cisa_kev' | 'nvd' | 'first_epss' | 'cisa_vulnrichment' | 'github_advisory' | 'osv';
  displayName: string;
  type: SourceType;
  purpose: string;
  provenanceUrl: string;
  authentication: SourceAuthentication;
  refreshSchedule: { cron: string; description: string };
  freshness: {
    state: SourceState;
    lastSuccessfulFetchAt: string | null;
    lastAttemptedFetchAt: string | null;
    minutesSinceSuccess: number | null;
    thresholdMinutes: number;
    partialReason?: string;
    unavailableReason?: string;
  };
  coverage: { enriched: number; total: number };
  limitations: string;
  backfill?: { cadenceDays: number; maxPerCycle: number };
}
