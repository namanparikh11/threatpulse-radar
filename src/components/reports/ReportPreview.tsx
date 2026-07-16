/**
 * V6.5 — Report preview.
 *
 * Renders the frozen JSON report as accessible
 * headings, label/value rows, and tables. The
 * component is React-text-only; it never uses
 * `dangerouslySetInnerHTML`. Every value is rendered
 * as a React text node, so user-authored content is
 * always escaped.
 *
 * The component does NOT mutate the workspace, does
 * NOT call the network, does NOT touch the URL or
 * history. The component reads the report object
 * passed in via props.
 *
 * Each section carries an inline metadata pill that
 * surfaces the field kind: "Provider fact",
 * "ThreatPulse-derived", "User-authored local field",
 * "System metadata", or "Unavailable or uncertain".
 */

import { describeField, fieldKindOf } from '../../reports/redaction.mjs';
import { shortChecksum } from '../../reports/integrity.mjs';

export interface ReportPreviewProps {
  report: any;
  /** When true, also show a small "checksum" pill at
   *  the top of the preview. The default is true. */
  showChecksum?: boolean;
}

const KIND_LABEL: Record<string, string> = {
  'provider-fact': 'Provider fact',
  'threatpulse-derived': 'ThreatPulse-derived',
  'user-authored': 'User-authored local field',
  'system-metadata': 'System metadata',
  'unavailable-or-uncertain': 'Unavailable or uncertain',
};

function valueToString(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function Pill({ kind }: { kind: string }) {
  if (!kind) return null;
  const label = KIND_LABEL[kind] || kind;
  const tone =
    kind === 'provider-fact' ? 'border-radar-accent/30 bg-radar-accent/10 text-radar-accent'
    : kind === 'threatpulse-derived' ? 'border-radar-warn/30 bg-radar-warn/10 text-radar-warn'
    : kind === 'user-authored' ? 'border-radar-muted/40 bg-radar-panel2 text-radar-text'
    : kind === 'unavailable-or-uncertain' ? 'border-radar-warn/40 bg-radar-warn/5 text-radar-warn'
    : 'border-radar-border bg-radar-panel2 text-radar-muted';
  return (
    <span
      className={['inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px]', tone].join(' ')}
      data-kind={kind}
    >
      {label}
    </span>
  );
}

function SectionHeading({ kind, title }: { kind: string; title: string }) {
  return (
    <h3 className="mt-4 mb-2 flex items-center gap-2 text-sm font-semibold text-radar-text">
      <span>{title || '(untitled section)'}</span>
      {kind && <Pill kind={kind} />}
    </h3>
  );
}

function KeyValueRows({ rows }: { rows: any[] }) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return <p className="text-[11px] text-radar-dim">No fields in this section.</p>;
  }
  return (
    <table className="w-full border-collapse text-[12px]">
      <caption className="sr-only">Section rows</caption>
      <tbody>
        {rows.map((r: any, i: number) => (
          <tr key={i} className="align-top">
            <th scope="row" className="w-1/3 border-b border-radar-border/40 px-2 py-1 text-left text-[11px] font-medium text-radar-muted">
              <span className="inline-flex items-center gap-1">
                {r.label || r.field || 'Field'}
                {r.kind && <Pill kind={r.kind} />}
              </span>
            </th>
            <td className="border-b border-radar-border/40 px-2 py-1 break-words text-radar-text">
              {valueToString(r.value)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CveBlock({ block }: { block: any }) {
  if (!block) return null;
  if (block.kind === 'cve-identifier-only') {
    return (
      <div className="rounded-md border border-radar-border bg-radar-panel2/40 px-3 py-2 text-[12px] text-radar-muted">
        <span className="font-mono text-radar-text">{block.cveId}</span>
        {' '}
        <span className="text-radar-dim">(identifier-only mode)</span>
      </div>
    );
  }
  if (block.kind !== 'cve-block') {
    return <pre className="text-[11px] text-radar-muted">{JSON.stringify(block, null, 2)}</pre>;
  }
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/30 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="font-mono text-sm text-radar-accent">{block.cveId}</span>
      </div>
      <KeyValueRows rows={block.rows} />
    </div>
  );
}

export default function ReportPreview({ report, showChecksum = true }: ReportPreviewProps) {
  if (!report || typeof report !== 'object') {
    return <p className="text-[12px] text-radar-warn">No report to preview.</p>;
  }
  const sections = Array.isArray(report.sections) ? report.sections : [];
  const limitations = Array.isArray(report.limitations) ? report.limitations : [];
  const provenance = Array.isArray(report.provenance) ? report.provenance : [];
  const sel = report.selection || {};
  const pi = report.publicIntelligence || {};
  const integ = report.integrity || {};
  const full = typeof integ.checksum === 'string' ? integ.checksum : '';
  const short = shortChecksum(full);
  return (
    <article
      className="report-preview max-h-[60vh] overflow-y-auto rounded-md border border-radar-border bg-radar-panel/60 p-4"
      data-testid="report-preview"
    >
      <header className="mb-3 border-b border-radar-border/40 pb-3">
        <div className="flex flex-wrap items-baseline gap-2">
          <h2 className="text-base font-semibold text-radar-text">{report.title || '(untitled)'}</h2>
          <span className="rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted">
            {report.reportType || 'unknown-type'}
          </span>
        </div>
        <dl className="mt-2 grid grid-cols-1 gap-1 text-[11px] text-radar-muted sm:grid-cols-2">
          <div><dt className="inline">Report ID: </dt><dd className="inline font-mono">{report.reportId}</dd></div>
          <div><dt className="inline">Generated: </dt><dd className="inline font-mono">{report.generatedAt}</dd></div>
          <div><dt className="inline">Application: </dt><dd className="inline font-mono">{report.applicationVersion}</dd></div>
          <div>
            <dt className="inline">Public intelligence: </dt>
            <dd className="inline font-mono">
              {pi.status || 'unavailable'}
              {pi.version ? ` · ${pi.version}` : ''}
            </dd>
          </div>
        </dl>
        {showChecksum && full && (
          <p
            className="mt-2 inline-flex items-center gap-2 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted"
            data-testid="report-preview-checksum"
          >
            <span>SHA-256:</span>
            <span className="font-mono">{short}</span>
            {short !== full && (
              <span className="text-radar-dim">(full digest stored in the JSON integrity block)</span>
            )}
          </p>
        )}
      </header>

      <section aria-label="Limitations" className="mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-radar-muted">Limitations</h3>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[12px] text-radar-text">
          {limitations.map((l: any, i: number) => (
            <li key={i}>{String(l)}</li>
          ))}
        </ul>
      </section>

      <section aria-label="Selection summary" className="mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-radar-muted">Selection</h3>
        <p className="mt-1 text-[12px] text-radar-muted">
          {Array.isArray(sel.cveIds) ? `${sel.cveIds.length} CVE${sel.cveIds.length === 1 ? '' : 's'}` : '0 CVEs'}
          {' · '}
          {sel.includePrivateNotes ? 'private notes included' : 'private notes excluded'}
          {' · '}
          {sel.includeLocalTags !== false ? 'local tags included' : 'local tags excluded'}
          {' · '}
          {sel.includeResolved ? 'resolved included' : 'resolved excluded'}
          {' · '}
          {sel.includeArchived ? 'archived included' : 'archived excluded'}
        </p>
      </section>

      {sections.length === 0 && (
        <p className="text-[12px] text-radar-warn">The report has no sections.</p>
      )}

      {sections.map((s: any, i: number) => (
        <section key={i} className="mb-3" aria-label={s.title || `Section ${i + 1}`}>
          <SectionHeading kind={s.kind || 'system-metadata'} title={s.title} />
          {s.kind === 'cve-list' && Array.isArray(s.body) ? (
            <div className="space-y-2">
              {s.body.map((b: any, j: number) => <CveBlock key={j} block={b} />)}
            </div>
          ) : (
            <KeyValueRows rows={s.body} />
          )}
        </section>
      ))}

      <section aria-label="Provenance" className="mt-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-radar-muted">Source provenance</h3>
        {provenance.length === 0 ? (
          <p className="mt-1 text-[12px] text-radar-dim">No public source metadata captured in this snapshot.</p>
        ) : (
          <table className="mt-1 w-full border-collapse text-[12px]">
            <caption className="sr-only">Source provenance</caption>
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-radar-muted">
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Source</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">State</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Last success</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Official link</th>
              </tr>
            </thead>
            <tbody>
              {provenance.map((p: any, i: number) => (
                <tr key={i} className="align-top">
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-text">{p.name || p.sourceId}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{p.state || 'unknown'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted font-mono">{p.lastSuccessAt || '—'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 break-all text-radar-accent">
                    {p.officialUrl ? (
                      <span className="font-mono">{p.officialUrl}</span>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </article>
  );
}

export { describeField, fieldKindOf };
