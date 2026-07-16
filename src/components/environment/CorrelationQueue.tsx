/**
 * V6.6 — Correlation queue.
 *
 * Aggregates the correlations across every asset +
 * inventory + component combination and surfaces
 * the queue to the operator. Per-CVE / per-asset
 * counts + state distribution are derived live from
 * the EnvironmentContext state.
 *
 * The component is purely presentational; the review
 * action is handled by `CorrelationReviewDialog`.
 */

import { useMemo, useState } from 'react';
import { useEnvironment } from '../../state/EnvironmentContext';
import { CORRELATION_STATES } from '../../environment/schema.mjs';
import CorrelationReviewDialog from './CorrelationReviewDialog';

export interface CorrelationQueueProps {
  assets: any[];
}

const STATE_LABEL: Record<string, string> = {
  'affected-range-match': 'Affected-range match',
  'exact-version-match': 'Exact-version match',
  'identity-only-potential': 'Identity-only potential',
  'version-not-evaluable': 'Version not evaluable',
  'public-data-unavailable': 'Public data unavailable',
  'no-supported-match': 'No supported match',
};

const STATE_TONE: Record<string, string> = {
  'affected-range-match': 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn',
  'exact-version-match': 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn',
  'identity-only-potential': 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent',
  'version-not-evaluable': 'border-radar-border bg-radar-panel2 text-radar-muted',
  'public-data-unavailable': 'border-radar-border bg-radar-panel2 text-radar-muted',
  'no-supported-match': 'border-radar-border bg-radar-panel2 text-radar-muted',
};

export default function CorrelationQueue({ assets }: CorrelationQueueProps) {
  const env = useEnvironment();
  const [reviewing, setReviewing] = useState<any | null>(null);

  const rows = useMemo(() => {
    const list: any[] = [];
    for (const a of assets) {
      for (const inv of (env.state.inventoriesByAsset[a.assetId] || [])) {
        const cs = env.state.correlationsByInventory[inv.inventoryId] || [];
        for (const c of cs) list.push({ ...c, assetName: a.name, assetId: a.assetId });
      }
    }
    list.sort((a, b) => {
      const c = String(a.state).localeCompare(String(b.state));
      if (c !== 0) return c;
      return String(a.cveId).localeCompare(String(b.cveId));
    });
    return list;
  }, [assets, env.state.inventoriesByAsset, env.state.correlationsByInventory]);

  const counts: Record<string, number> = useMemo(() => {
    const out: Record<string, number> = {};
    for (const s of CORRELATION_STATES) out[s] = 0;
    for (const r of rows) out[r.state] = (out[r.state] || 0) + 1;
    return out;
  }, [rows]);

  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-radar-border bg-radar-panel2/30 px-3 py-3 text-center text-[11px] text-radar-dim">
        No correlations yet. Import an inventory to compute potential local relevance.
      </div>
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {CORRELATION_STATES.map((s) => counts[s] > 0 ? (
          <span
            key={s}
            className={['inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px]', STATE_TONE[s] || 'border-radar-border bg-radar-panel2 text-radar-muted'].join(' ')}
            data-testid={`correlation-count-${s}`}
          >
            {STATE_LABEL[s]}: {counts[s]}
          </span>
        ) : null)}
      </div>
      <div className="rounded-md border border-radar-border bg-radar-panel2/40">
        <table className="w-full border-collapse text-[12px]">
          <caption className="sr-only">Local correlations</caption>
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider text-radar-muted">
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Asset</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">CVE</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Component</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">State</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Review</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 50).map((r) => {
              const review = env.state.reviewsByCorrelation && env.state.reviewsByCorrelation[r.correlationId];
              return (
                <tr key={r.correlationId} className="align-top">
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-text">{r.assetName}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 font-mono text-radar-muted">{r.cveId}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 font-mono text-radar-muted">{r.componentId}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1">
                    <span className={['inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px]', STATE_TONE[r.state] || 'border-radar-border bg-radar-panel2 text-radar-muted'].join(' ')}>
                      {STATE_LABEL[r.state] || r.state}
                    </span>
                  </td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">
                    <button
                      type="button"
                      onClick={() => setReviewing(r)}
                      className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
                      data-testid={`correlation-review-${r.correlationId}`}
                    >
                      {review ? review.reviewStatus : 'unreviewed'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length > 50 && <p className="px-2 py-1 text-[10px] text-radar-dim">Showing the first 50 of {rows.length} correlation(s).</p>}
      </div>
      {reviewing && (
        <CorrelationReviewDialog
          correlation={reviewing}
          onClose={() => setReviewing(null)}
        />
      )}
    </>
  );
}
