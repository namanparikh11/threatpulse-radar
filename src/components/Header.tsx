import {
  CircleAlert,
  Clock,
  Cloud,
  Database,
  FlaskConical,
  Gauge,
  HardDrive,
  Loader2,
  Radar,
  Satellite,
  ShieldCheck,
  TrendingUp,
} from 'lucide-react';
import type { ReactNode } from 'react';
import type { FetchResult } from '../services/vulnerabilityService';
import type { Vulnerability } from '../types/vulnerability';
import { formatAbsolute, formatRelative } from '../utils/format';

interface HeaderProps {
  meta: FetchResult<Vulnerability[]> | null;
}

type Tone = 'good' | 'info' | 'neutral' | 'warn';

const TONE_DOT: Record<Tone, string> = {
  good: 'bg-radar-accent2',
  info: 'bg-radar-accent',
  neutral: 'bg-radar-dim',
  warn: 'bg-radar-warn',
};

const TONE_CHIP: Record<Tone, string> = {
  good: 'border-radar-accent2/30 bg-radar-accent2/5 text-radar-accent2',
  info: 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent',
  neutral: 'border-radar-border bg-radar-panel2/60 text-radar-muted',
  warn: 'border-radar-warn/30 bg-radar-warn/5 text-radar-warn',
};

function StatusPill({
  icon,
  label,
  tone,
  pulse,
  title,
}: {
  icon: ReactNode;
  label: string;
  tone: Tone;
  pulse?: boolean;
  title?: string;
}) {
  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${TONE_CHIP[tone]}`}
      title={title}
    >
      <span
        className={[
          'h-1.5 w-1.5 rounded-full',
          TONE_DOT[tone],
          pulse ? 'animate-pulseDot' : '',
        ].join(' ')}
      />
      {icon}
      <span>{label}</span>
    </div>
  );
}

function MetaBadge({
  icon,
  label,
  tone,
}: {
  icon: ReactNode;
  label: string;
  tone: 'accent' | 'warn';
}) {
  const toneClass =
    tone === 'accent'
      ? 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent'
      : 'border-radar-warn/30 bg-radar-warn/5 text-radar-warn';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${toneClass}`}
    >
      {icon}
      {label}
    </span>
  );
}

/**
 * Map the service's (source, mode, nvdStatus, epssStatus) tuple to a
 * human-readable label for the source pill. The label only lists a
 * provider if it actually contributed data — the amber "unavailable"
 * pills make failures obvious, but the source label must not
 * overstate the composition.
 *
 * Kept in one place so the header is the only place the wording lives.
 */
function describeSource(
  source: FetchResult<Vulnerability[]>['source'] | undefined,
  mode: FetchResult<Vulnerability[]>['mode'] | undefined,
  nvdStatus: FetchResult<Vulnerability[]>['nvdStatus'] | undefined,
  epssStatus: FetchResult<Vulnerability[]>['epssStatus'] | undefined
): string {
  if (!source) return 'loading';
  // Fallback always means the user is seeing mock data despite
  // the app being in 'live' mode — say so explicitly.
  if (mode === 'fallback') return 'mock (fallback)';
  if (source === 'cisa-kev') return 'CISA KEV';
  if (source === 'nvd') return 'NVD';
  if (source === 'epss') return 'FIRST EPSS';
  if (source === 'merged') {
    // Build the label from the actual status of each provider.
    // Don't mention a provider in the source label if its pill
    // is showing the amber "unavailable" state.
    const parts: string[] = ['CISA KEV'];
    if (nvdStatus === 'nvd') parts.push('NVD');
    if (epssStatus === 'first') parts.push('FIRST EPSS');
    return parts.join(' + ');
  }
  return 'mock';
}

export default function Header({ meta }: HeaderProps) {
  const fetchedAt = meta?.fetchedAt ? formatRelative(meta.fetchedAt) : '—';
  const epssStatus = meta?.epssStatus;
  const nvdStatus = meta?.nvdStatus;
  const sourceLabel = describeSource(
    meta?.source,
    meta?.mode,
    nvdStatus,
    epssStatus
  );
  const isLive = meta?.mode === 'live';
  const isFallback = meta?.mode === 'fallback';
  const isMock = meta?.mode === 'mock';
  // v4: cache provenance drives the new "Cache:" pill. The pill
  // is intentionally distinct from the mode pills (which answer
  // "what data is this?") — cacheStatus answers "where did this
  // particular result come from on this load?".
  const cacheStatus = meta?.cacheStatus;
  // v5.2: where the data came from on the server. Drives the
  // "Dataset store:" pill. Distinct from `proxyStatus` (which
  // answers "which transport carried the live data, when there
  // was any"). The Dataset store pill is the v5.2 honest signal
  // that the visitor is reading from a shared blob, not paying
  // a live build on this request.
  const dataSource = meta?.dataSource;
  // v5.2: refresh-lock state. Drives the "Refresh running in
  // background" pill. Independent of the dataset envelope —
  // even a successful cached read can have `refreshInProgress:
  // true` if a background rebuild is underway.
  const refreshInProgress = meta?.refreshInProgress === true;

  return (
    <header className="relative isolate overflow-hidden border-b border-radar-border bg-radar-bg/85 backdrop-blur-md">
      {/*
        Decorative background: dot grid + two soft glow blobs.
        Sits behind the content via `-z-10`. Subtle, never loud.
      */}
      <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden>
        <div className="absolute inset-0 opacity-[0.06] [background-image:radial-gradient(rgba(148,163,184,0.9)_1px,transparent_1px)] [background-size:22px_22px]" />
        <div className="absolute -top-32 right-[-8%] h-64 w-[28rem] rounded-full bg-radar-accent/12 blur-3xl" />
        <div className="absolute -bottom-24 left-[5%] h-48 w-[24rem] rounded-full bg-radar-accent2/10 blur-3xl" />
      </div>

      {/* Main hero area — single, clean, no top status strip. */}
      <div className="mx-auto max-w-[1400px] px-4 py-7 lg:px-8 lg:py-9">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between lg:gap-12">
          {/* Brand */}
          <div className="flex min-w-0 items-start gap-4">
            <div className="relative grid h-14 w-14 shrink-0 place-items-center rounded-xl border border-radar-borderStrong bg-radar-panel2 shadow-glow lg:h-16 lg:w-16">
              <Radar className="h-7 w-7 text-radar-accent lg:h-8 lg:w-8" />
              <span className="pointer-events-none absolute inset-0 rounded-xl ring-1 ring-radar-accent/20" />
              <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-radar-accent shadow-[0_0_8px_rgba(34,211,238,0.7)] animate-pulseDot" />
            </div>
            <div className="min-w-0 flex-1">
              <h1 className="text-[1.65rem] font-bold leading-[1.1] tracking-tight text-radar-text sm:text-3xl lg lg:text-[2.4rem]">
                ThreatPulse Radar
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-radar-muted sm:text-[0.95rem]">
                Defensive vulnerability intelligence dashboard for tracking risk,
                exploitation signals, and remediation priorities.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                {isLive && (
                  <MetaBadge
                    icon={<Satellite className="h-3 w-3" />}
                    label="Live CISA KEV Mode"
                    tone="accent"
                  />
                )}
                {isFallback && (
                  <MetaBadge
                    icon={<CircleAlert className="h-3 w-3" />}
                    label="Fallback Mode"
                    tone="warn"
                  />
                )}
                {isMock && (
                  <MetaBadge
                    icon={<FlaskConical className="h-3 w-3" />}
                    label="Mock Data Mode"
                    tone="warn"
                  />
                )}
              </div>
            </div>
          </div>

          {/* Status column */}
          <div className="flex flex-row flex-wrap gap-2 lg:flex-col lg:items-end lg:gap-2">
            <StatusPill
              icon={<ShieldCheck className="h-3 w-3" />}
              label="Defensive use only"
              tone="good"
              pulse
              title="This dashboard is for defensive security work only"
            />
            <StatusPill
              icon={<Database className="h-3 w-3" />}
              label={`Source: ${sourceLabel}`}
              tone={isFallback ? 'warn' : 'info'}
              title={
                meta?.fallbackReason
                  ? `Current data source — live fetch failed: ${meta.fallbackReason}`
                  : 'Current data source'
              }
            />
            {nvdStatus === 'nvd' && (
              <StatusPill
                icon={<Gauge className="h-3 w-3" />}
                label="NVD: enriched"
                tone="info"
                title="CVSS scores enriched from the NVD CVE 2.0 feed"
              />
            )}
            {nvdStatus === 'unavailable' && (
              <StatusPill
                icon={<Gauge className="h-3 w-3" />}
                label="NVD: unavailable"
                tone="warn"
                title={
                  meta?.nvdReason
                    ? `NVD CVSS enrichment failed: ${meta.nvdReason}`
                    : 'NVD CVSS enrichment failed; scores default to 0'
                }
              />
            )}
            {epssStatus === 'first' && (
              <StatusPill
                icon={<TrendingUp className="h-3 w-3" />}
                label="EPSS: FIRST"
                tone="info"
                title="Exploitation probability scores enriched from FIRST EPSS"
              />
            )}
            {epssStatus === 'unavailable' && (
              <StatusPill
                icon={<TrendingUp className="h-3 w-3" />}
                label="EPSS: unavailable"
                tone="warn"
                title={
                  meta?.epssReason
                    ? `FIRST EPSS enrichment failed: ${meta.epssReason}`
                    : 'FIRST EPSS enrichment failed; scores default to 0'
                }
              />
            )}
            {cacheStatus === 'fresh' && (
              <StatusPill
                icon={<HardDrive className="h-3 w-3" />}
                label="Cache: fresh"
                tone="info"
                title="Served from local cache (within 1-hour TTL). Provider failures shown above are from the original fetch."
              />
            )}
            {cacheStatus === 'stale' && (
              <StatusPill
                icon={<HardDrive className="h-3 w-3" />}
                label="Cache: stale"
                tone="warn"
                title="Served from expired local cache because the live fetch failed. Data refreshes automatically in the background; the latest successfully enriched dataset remains available during provider delays."
              />
            )}
            {meta?.proxyStatus === 'proxy' && (
              <StatusPill
                icon={<Cloud className="h-3 w-3" />}
                label="Proxy: Netlify"
                tone="info"
                title="Live data was aggregated server-side by the Netlify Function at /.netlify/functions/dataset — the browser never hit the upstream feeds directly."
              />
            )}
            {/*
              v5.2: Dataset-store pill. Surfaced whenever the
              current FetchResult came from the shared Netlify
              Blobs entry (the v5.2 fast path). Tells the user
              they're reading from the prebuilt store, not paying
              a live build on this request. Distinct from the
              "Proxy: Netlify" pill which describes the transport
              layer rather than the storage layer.
            */}
            {dataSource === 'prebuilt-store' && (
              <StatusPill
                icon={<Database className="h-3 w-3" />}
                label="Dataset store: latest available"
                tone="info"
                title="This dataset was served from the shared Netlify Blobs store (v5.2 prebuilt dataset). A scheduled refresh rebuilds the store every 30 minutes. Data refreshes automatically in the background; the latest successfully enriched dataset remains available during provider delays."
              />
            )}
            {dataSource === 'live-build' && (
              <StatusPill
                icon={<Database className="h-3 w-3" />}
                label="Dataset store: bootstrapping"
                tone="neutral"
                title="No prebuilt dataset existed yet — this build ran live and was written to the shared store. Subsequent visitors will hit the fast path."
              />
            )}
            {/*
              v5.2: Refresh-in-progress pill. Surfaced when the
              refresh-lock blob is active (non-expired). The user
              knows a newer dataset is on the way; the existing
              v5.1 polling will detect it and surface the
              "New dataset available" banner.
            */}
            {refreshInProgress && (
              <StatusPill
                icon={<Loader2 className="h-3 w-3 animate-spin" />}
                label="Refresh running in background"
                tone="info"
                pulse
                title="A scheduled or manual refresh is currently rebuilding the shared dataset. Your current view is unchanged; the new dataset will appear via the 'New dataset available' banner."
              />
            )}
            <StatusPill
              icon={<Clock className="h-3 w-3" />}
              label={`Last refresh: ${fetchedAt}`}
              tone="neutral"
              title={
                meta?.fetchedAt
                  ? `Last dataset build: ${formatAbsolute(meta.fetchedAt)}`
                  : 'When the dataset was last fetched'
              }
            />
          </div>
        </div>
      </div>
    </header>
  );
}