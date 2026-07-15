/**
 * V6.1 — Expanded per-source detail card.
 *
 * Renders the source's full status: purpose, limitations,
 * official-source link, refresh schedule, threshold,
 * coverage, and (for incremental sources) backfill
 * metadata. The state-specific reason is rendered as a
 * small "i" tooltip on the state chip in the parent
 * component.
 */

import { ExternalLink, Info, X } from 'lucide-react';
import type { SourceStatus } from '../types/sourceHealth';

interface SourceStatusCardProps {
  source: SourceStatus;
  onClose: () => void;
}

export default function SourceStatusCard({ source, onClose }: SourceStatusCardProps) {
  const { freshness } = source;
  const reason = freshness.partialReason || freshness.unavailableReason;
  return (
    <div
      id={`source-detail-${source.id}`}
      role="region"
      aria-label={`Source detail: ${source.displayName}`}
      className="mt-3 rounded-md border border-radar-border bg-radar-panel2/60 p-4"
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-radar-text">{source.displayName}</div>
          <div className="mt-0.5 text-[11px] text-radar-dim">{source.purpose}</div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label={`Close ${source.displayName} detail`}
          className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted transition hover:text-radar-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {reason ? (
        <div className="mt-3 flex items-start gap-1.5 rounded-md border border-radar-border bg-radar-panel/60 p-2.5 text-[11px] text-radar-muted">
          <Info className="mt-0.5 h-3 w-3 shrink-0 text-radar-dim" />
          <p>{reason}</p>
        </div>
      ) : null}

      <dl className="mt-3 grid grid-cols-1 gap-2 text-[11px] text-radar-dim sm:grid-cols-2">
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Type</dt>
          <dd className="mt-0.5 text-radar-text capitalize">{source.type}</dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Authentication</dt>
          <dd className="mt-0.5 text-radar-text">
            {source.authentication === 'none'
              ? 'None (public)'
              : source.authentication === 'optional-server-side'
                ? 'Optional server-side'
                : 'Required server-side'}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Refresh</dt>
          <dd className="mt-0.5 text-radar-text">
            <code className="font-mono">{source.refreshSchedule.cron}</code>{' '}
            <span className="text-radar-dim">— {source.refreshSchedule.description}</span>
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Stale threshold</dt>
          <dd className="mt-0.5 text-radar-text">
            {source.freshness.thresholdMinutes} min
            {freshness.minutesSinceSuccess !== null ? (
              <span className="ml-1 text-radar-dim">
                (last good {freshness.minutesSinceSuccess} min ago)
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Coverage</dt>
          <dd className="mt-0.5 text-radar-text">
            {source.coverage.enriched.toLocaleString('en-US')} of{' '}
            {source.coverage.total.toLocaleString('en-US')}
          </dd>
        </div>
        {source.backfill ? (
          <div>
            <dt className="font-medium uppercase tracking-wider text-radar-muted">Backfill</dt>
            <dd className="mt-0.5 text-radar-text">
              {source.backfill.maxPerCycle} CVEs per cycle, {source.backfill.cadenceDays}-day cadence
            </dd>
          </div>
        ) : null}
        <div className="sm:col-span-2">
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Limitations</dt>
          <dd className="mt-0.5 text-radar-text">{source.limitations}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Official source</dt>
          <dd className="mt-0.5">
            <a
              href={source.provenanceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="focus-ring inline-flex items-center gap-1.5 text-radar-accent underline-offset-2 hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              <span>{source.provenanceUrl}</span>
            </a>
          </dd>
        </div>
      </dl>
    </div>
  );
}
