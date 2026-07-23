/**
 * V6.6 — Drawer "Potential local relevance" section.
 *
 * Surfaces the local correlation summary for the
 * open CVE. The section:
 *   - shows per-state counts (affected-range,
 *     exact-version, identity-only, etc.)
 *   - lists the matching local assets + components
 *   - shows the current review status (if any)
 *   - exposes the local review / dismiss actions
 *     so the operator can mark the correlation
 *     without leaving the drawer
 *
 * The section is render-only. All mutations go
 * through the EnvironmentContext.
 *
 * The section NEVER:
 *   - writes to the URL / history
 *   - logs to the console
 *   - includes private content in the document
 *     title or any non-text attribute
 */

import { useEffect, useState } from 'react';
import { useEnvironment } from '../../state/EnvironmentContext';
import { CORRELATION_STATES } from '../../environment/schema.mjs';

const STATE_LABEL: Record<string, string> = {
  'affected-range-match': 'Affected-range match',
  'exact-version-match': 'Exact-version match',
  'identity-only-potential': 'Identity-only potential',
  'version-not-evaluable': 'Version not evaluable',
  'public-data-unavailable': 'Public data unavailable',
  'no-supported-match': 'No supported match',
};

export interface LocalRelevanceSectionProps {
  cveId: string;
}

export default function LocalRelevanceSection({ cveId }: LocalRelevanceSectionProps) {
  const env = useEnvironment();
  const [correlations, setCorrelations] = useState<any[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const list: any[] = [];
      for (const a of env.state.assets) {
        for (const inv of (env.state.inventoriesByAsset[a.assetId] || [])) {
          const cs = env.state.correlationsByInventory[inv.inventoryId] || [];
          for (const c of cs) {
            if (c.cveId === cveId) list.push({ ...c, assetName: a.name, assetId: a.assetId });
          }
        }
      }
      if (!cancelled) setCorrelations(list);
    })();
    return () => { cancelled = true; };
  }, [cveId, env.state.assets, env.state.inventoriesByAsset, env.state.correlationsByInventory]);

  if (correlations === null) return null;
  if (correlations.length === 0) {
    return (
      <p className="text-[11px] text-radar-dim" data-testid="local-relevance-empty">
        No local correlation for {cveId} in the current environment.
      </p>
    );
  }

  const counts: Record<string, number> = {};
  for (const s of CORRELATION_STATES) counts[s] = 0;
  for (const c of correlations) counts[c.state] = (counts[c.state] || 0) + 1;

  const handleDismiss = async (correlationId: string) => {
    setBusy(true);
    setError(null);
    try {
      const r = await env.saveReview(correlationId, 'dismissed', '');
      if (!r.ok) setError(r.reason);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2" data-testid="local-relevance-section">
      <p className="text-[11px] text-radar-muted" data-testid="local-relevance-preamble">
        Potential local relevance for {cveId} based on imported component identity and available public data. It does not prove exploitability or compromise.
      </p>
      <div className="flex flex-wrap items-center gap-1">
        {CORRELATION_STATES.map((s) => counts[s] > 0 ? (
          <span
            key={s}
            className="inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted"
            data-testid={`local-relevance-count-${s}`}
          >
            {STATE_LABEL[s]}: {counts[s]}
          </span>
        ) : null)}
      </div>
      <ul className="space-y-1">
        {correlations.slice(0, 10).map((c) => {
          const review = env.state.reviewsByCorrelation && env.state.reviewsByCorrelation[c.correlationId];
          return (
            <li key={c.correlationId} className="rounded-md border border-radar-border bg-radar-panel2/30 px-2 py-1 text-[11px]">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-medium text-radar-text">{c.assetName}</span>
                <span className="font-mono text-radar-muted">{c.componentId}</span>
                <span className="text-radar-dim">v{c.importedVersion || '—'}</span>
              </div>
              <div className="mt-1 text-[10px] text-radar-dim">
                State: {STATE_LABEL[c.state] || c.state}
                {c.providerSources && c.providerSources.length > 0 ? ` · Source: ${c.providerSources.join(', ')}` : ''}
                {review ? ` · Review: ${review.reviewStatus}` : ''}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-1">
                {(!review || review.reviewStatus !== 'dismissed') && (
                  <button
                    type="button"
                    onClick={() => handleDismiss(c.correlationId)}
                    disabled={busy}
                    className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn disabled:opacity-50"
                    data-testid={`local-relevance-dismiss-${c.correlationId}`}
                  >
                    Dismiss
                  </button>
                )}
              </div>
            </li>
          );
        })}
        {correlations.length > 10 && <li className="text-[10px] text-radar-dim">Showing 10 of {correlations.length}.</li>}
      </ul>
      {error && <p className="text-[11px] text-radar-warn" data-testid="local-relevance-error">{error}</p>}
    </div>
  );
}
