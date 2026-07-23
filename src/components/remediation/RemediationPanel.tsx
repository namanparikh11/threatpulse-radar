/**
 * V6.7 — Local remediation dashboard panel.
 *
 * Compact summary of the local remediation database
 * with the documented count cards (active, draft,
 * planned, in-progress, blocked, overdue, validation
 * pending, completed, accepted risk, broken ledger)
 * and the documented filter chips. The panel is the
 * dashboard-level entry point to plan management.
 *
 * The panel does NOT enter any of its filter state
 * into the public URL. Each filter change is a
 * `useState` update inside the panel; the public URL
 * never reflects local remediation filters.
 */
import { useEffect, useMemo, useState } from 'react';
import { useRemediation } from '../../state/RemediationContext';
import { PlanList, type RemediationFilter } from './PlanList';

const FILTER_LABELS: Record<RemediationFilter, string> = {
  'all-active': 'All active',
  'due-soon': 'Due soon',
  'overdue': 'Overdue',
  'blocked': 'Blocked',
  'validation-pending': 'Validation pending',
  'completed': 'Completed',
  'accepted-risk': 'Accepted risk',
  'archived': 'Archived',
  'broken-ledger': 'Broken ledger',
};

interface RemediationPanelProps {
  onExportPlan(planId: string): void;
}

export function RemediationPanel({ onExportPlan }: RemediationPanelProps) {
  const ctx = useRemediation();
  const [selectedPlanId, setSelectedPlanId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void ctx.verifyAllLedgers();
  }, [ctx.state.plans.length, ctx.state.tasksByPlan, ctx.state.evidenceByPlan]);

  const counts = useMemo(() => ctx.countByStatus(), [ctx.state.plans]);
  const totalActive = ctx.state.plans.filter((p: any) => !p.archived && p.status !== 'completed' && p.status !== 'cancelled' && p.status !== 'accepted-risk').length;
  const totalArchived = ctx.state.plans.filter((p: any) => p.archived).length;
  const overdue = useMemo(() => ctx.state.plans.filter((p: any) => {
    if (p.archived) return false;
    if (p.status === 'completed' || p.status === 'cancelled' || p.status === 'accepted-risk') return false;
    if (typeof p.dueAt !== 'string' || p.dueAt.length === 0) return false;
    return Date.parse(p.dueAt) < Date.now();
  }).length, [ctx.state.plans]);
  const brokenCount = useMemo(() => Object.values(ctx.state.ledgerVerification.perPlan).filter((v: any) => v && !v.ok).length, [ctx.state.ledgerVerification.perPlan]);

  const onClearAll = async () => {
    if (typeof window === 'undefined') return;
    if (!window.confirm('Clear ALL local remediation data? This deletes every plan, task, evidence record, and ledger event. This cannot be undone.')) return;
    setError(null);
    const r = await ctx.clearAll();
    if (!r.ok) setError(r.reason || 'clear-failed');
  };

  return (
    <section className="panel space-y-3 px-4 py-4" aria-label="Local remediation" data-testid="remediation-panel">
      <header className="space-y-1">
        <h2 className="text-sm font-semibold text-radar-text">Local remediation</h2>
        <p className="text-[11px] text-radar-muted" data-testid="remediation-privacy-preamble">
          Remediation plans and evidence are stored only in this browser. Completion and validation states are locally recorded workflow information, not an independent ThreatPulse verification.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2" data-testid="remediation-status">
        {ctx.state.status === 'initializing' && (
          <span className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted" aria-busy="true">Initialising local remediation…</span>
        )}
        {ctx.state.status === 'session-only' && (
          <span className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[11px] text-radar-warn" data-testid="remediation-status-session-only">
            Session-only — data will not survive a tab close
          </span>
        )}
        {ctx.state.status === 'unavailable' && (
          <span className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[11px] text-radar-warn" data-testid="remediation-status-unavailable">
            Local remediation is unavailable in this browser session. {ctx.state.lastError ? `(${ctx.state.lastError})` : ''}
          </span>
        )}
        {brokenCount > 0 && (
          <span className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[11px] text-radar-warn" data-testid="remediation-status-broken-ledger">
            {brokenCount} plan{brokenCount === 1 ? '' : 's'} with a broken ledger chain
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <CountCard label="Active" value={totalActive} />
        <CountCard label="Draft" value={counts.draft || 0} />
        <CountCard label="Planned" value={counts.planned || 0} />
        <CountCard label="In progress" value={counts['in-progress'] || 0} />
        <CountCard label="Blocked" value={counts.blocked || 0} />
        <CountCard label="Overdue" value={overdue} />
        <CountCard label="Validation pending" value={(counts['validation-pending'] || 0) + ctx.state.plans.filter((p: any) => !p.archived && p.validationStatus === 'pending').length} />
        <CountCard label="Completed" value={counts.completed || 0} />
        <CountCard label="Accepted risk" value={counts['accepted-risk'] || 0} />
        <CountCard label="Archived" value={totalArchived} />
      </div>

      {error && (
        <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="remediation-error">{error}</p>
      )}

      {ctx.state.status !== 'unavailable' && (
        <PlanList
          onExport={onExportPlan}
          onSelectPlan={setSelectedPlanId}
          selectedPlanId={selectedPlanId || undefined}
        />
      )}

      {ctx.state.status !== 'unavailable' && (
        <div className="flex flex-col gap-2 border-t border-radar-border/40 pt-3 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            onClick={onClearAll}
            disabled={ctx.state.plans.length === 0}
            className="focus-ring inline-flex items-center gap-1 self-start rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn disabled:opacity-50 sm:self-auto"
            data-testid="remediation-clear-button"
          >
            Clear all remediation data
          </button>
          <p className="text-[10px] text-radar-dim">{FILTER_LABELS['all-active']} (default) · local filter state is not stored in the URL</p>
        </div>
      )}
    </section>
  );
}

function CountCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/30 p-2 text-[11px]">
      <div className="text-radar-muted">{label}</div>
      <div className="mt-1 text-base font-semibold text-radar-text" data-testid={`remediation-count-${label.replace(/\s+/g, '-').toLowerCase()}`}>{value}</div>
    </div>
  );
}
