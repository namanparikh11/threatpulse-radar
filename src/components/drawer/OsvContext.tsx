/**
 * V6.1 — OSV section in the DetailDrawer.
 *
 * Renders the bounded per-CVE public OSV projection for
 * the selected vulnerability. The data is fetched on
 * drawer open via the dataset function's `view=osv`
 * query mode and attached to `vuln.osv` (lazy; the
 * parent DashboardPage is responsible for the fetch).
 *
 * The section is source-distinct from the GitHub Advisory
 * section. Provider-native ranges are preserved verbatim
 * (no flattening, no GitHub-OSV range synthesis). Truncated
 * fields are surfaced explicitly.
 *
 * Empty-state copy (locked):
 *   "No OSV record is currently available in this
 *    ThreatPulse snapshot."
 *
 * This copy refers to "this ThreatPulse snapshot" — the
 * public tracked universe at the current public-
 * intelligence version — and does NOT claim global
 * absence.
 */

import { ExternalLink } from 'lucide-react';
import type { Vulnerability } from '../../types/vulnerability';
import type {
  OsvPublicContext,
  OsvPublicRecord,
  OsvAffectedPackage,
  OsvRange,
  OsvEvent,
} from '../../types/osv';

export default function OsvContext({ vuln }: { vuln: Vulnerability }) {
  const osv: OsvPublicContext | null | undefined = vuln.osv;
  if (!osv || !Array.isArray(osv.records) || osv.records.length === 0) {
    return (
      <p className="rounded-md border border-radar-border bg-radar-panel2/60 p-3 text-xs text-radar-muted">
        No OSV record is currently available in this ThreatPulse snapshot.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      {osv.records.map((rec) => (
        <OsvRecord key={rec.osvId} record={rec} />
      ))}
      {osv.truncation && osv.truncation.recordsRemoved > 0 ? (
        <p className="text-[11px] text-radar-dim">
          {osv.truncation.recordsRemoved} additional OSV record
          {osv.truncation.recordsRemoved === 1 ? '' : 's'} suppressed
          by the per-CVE cap. See the official OSV record for the
          complete list.
        </p>
      ) : null}
    </div>
  );
}

function OsvRecord({ record }: { record: OsvPublicRecord }) {
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/60 p-3">
      <dl className="grid grid-cols-1 gap-2 text-[11px] text-radar-dim sm:grid-cols-2">
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">OSV id</dt>
          <dd className="mt-0.5">
            <a
              href={`https://osv.dev/vulnerability/${encodeURIComponent(record.osvId)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="focus-ring inline-flex items-center gap-1.5 text-radar-accent underline-offset-2 hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              <span className="font-mono">{record.osvId}</span>
            </a>
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Ecosystem</dt>
          <dd className="mt-0.5 text-radar-text">{record.sourceDatabase}</dd>
        </div>
        {record.aliases && record.aliases.length > 0 ? (
          <div className="sm:col-span-2">
            <dt className="font-medium uppercase tracking-wider text-radar-muted">Aliases</dt>
            <dd className="mt-0.5 text-radar-text">
              {record.aliases.slice(0, 5).join(', ')}
              {record.aliases.length > 5 ? ` + ${record.aliases.length - 5} more` : ''}
            </dd>
          </div>
        ) : null}
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Modified</dt>
          <dd className="mt-0.5 text-radar-text">{record.modifiedAt || 'Unknown'}</dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">Status</dt>
          <dd className="mt-0.5 text-radar-text">
            {record.withdrawn ? (
              <span className="chip border-radar-warn/40 bg-radar-warn/10 text-radar-warn">Withdrawn</span>
            ) : (
              <span className="chip border-radar-accent/40 bg-radar-accent/10 text-radar-accent">Active</span>
            )}
          </dd>
        </div>
      </dl>
      {Array.isArray(record.affectedPackages) && record.affectedPackages.length > 0 ? (
        <div className="mt-3">
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-radar-muted">
            Affected packages
          </div>
          <ul className="space-y-2">
            {record.affectedPackages.map((pkg, idx) => (
              <OsvPackageEntry
                key={`${pkg.ecosystem}-${pkg.name}-${idx}`}
                pkg={pkg}
              />
            ))}
          </ul>
        </div>
      ) : null}
      {record.truncation.aliasesRemoved > 0 ||
      record.truncation.referencesRemoved > 0 ||
      record.truncation.packagesRemoved > 0 ? (
        <p className="mt-2 text-[10px] text-radar-dim">
          Truncated: {record.truncation.aliasesRemoved} aliases,{' '}
          {record.truncation.referencesRemoved} references,{' '}
          {record.truncation.packagesRemoved} packages omitted.
        </p>
      ) : null}
    </div>
  );
}

function OsvPackageEntry({ pkg }: { pkg: OsvAffectedPackage }) {
  return (
    <li className="rounded-md border border-radar-border bg-radar-panel/60 p-2.5">
      <div className="flex items-baseline justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-radar-text">
            <span className="text-radar-muted">{pkg.ecosystem}</span>
            <span className="px-1 text-radar-dim">/</span>
            <span className="font-mono">{pkg.name}</span>
          </div>
          {Array.isArray(pkg.ranges) && pkg.ranges.length > 0 ? (
            <div className="mt-1 space-y-1">
              {pkg.ranges.map((r, idx) => (
                <OsvRangeRow key={idx} rangeType={r.type} events={r.events} />
              ))}
            </div>
          ) : null}
        </div>
        <div className="shrink-0 text-right text-[10px] text-radar-dim">
          <div className="uppercase tracking-wider text-radar-muted">First fixed</div>
          <div className="mt-0.5 font-mono text-sm text-radar-text">
            {formatOsvFirstFixed(pkg.ranges || [])}
          </div>
        </div>
      </div>
    </li>
  );
}

function OsvRangeRow({
  rangeType,
  events,
}: {
  rangeType: string;
  events: OsvEvent[];
}) {
  if (!Array.isArray(events) || events.length === 0) return null;
  const evStr = events
    .map((e) => {
      if (e.introduced) return `[introduced: ${e.introduced}]`;
      if (e.fixed) return `[fixed: ${e.fixed}]`;
      if (e.last_affected) return `[last_affected: ${e.last_affected}]`;
      if (e.limit) return `[limit: ${e.limit}]`;
      return '';
    })
    .filter(Boolean)
    .join(' ');
  return (
    <div className="text-[10px] text-radar-dim">
      <span className="uppercase tracking-wider text-radar-muted">
        {rangeType}:
      </span>{' '}
      <code className="font-mono text-radar-text">{evStr}</code>
    </div>
  );
}

function formatOsvFirstFixed(ranges: OsvRange[]): string {
  if (!Array.isArray(ranges) || ranges.length === 0) return 'unavailable';
  for (const r of ranges) {
    if (!Array.isArray(r.events)) continue;
    for (const e of r.events) {
      if (e.fixed) return e.fixed;
    }
    for (const e of r.events) {
      if (e.last_affected)
        return `unavailable (last affected: ${e.last_affected})`;
    }
  }
  return 'unavailable';
}
