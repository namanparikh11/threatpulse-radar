/**
 * V6.7 — Plan list.
 *
 * Compact list of plans matching the current filter.
 * Selecting a plan opens the PlanDetail view. The
 * list is the surface for the dashboard's "Remediation
 * plans" panel.
 */
import { useEffect, useMemo, useState } from 'react';
import { useRemediation } from '../../state/RemediationContext';
import { PlanDialog } from './PlanDialog';
import { PlanDetail } from './PlanDetail';

export type RemediationFilter = 'all-active' | 'due-soon' | 'overdue' | 'blocked' | 'validation-pending' | 'completed' | 'accepted-risk' | 'archived' | 'broken-ledger';

const FILTERS: { id: RemediationFilter; label: string }[] = [
  { id: 'all-active', label: 'All active' },
  { id: 'due-soon', label: 'Due soon' },
  { id: 'overdue', label: 'Overdue' },
  { id: 'blocked', label: 'Blocked' },
  { id: 'validation-pending', label: 'Validation pending' },
  { id: 'completed', label: 'Completed' },
  { id: 'accepted-risk', label: 'Accepted risk' },
  { id: 'archived', label: 'Archived' },
  { id: 'broken-ledger', label: 'Broken ledger' },
];

function isOverdue(plan: any): boolean {
  if (!plan || plan.archived) return false;
  if (plan.status === 'completed' || plan.status === 'cancelled' || plan.status === 'accepted-risk') return false;
  if (typeof plan.dueAt !== 'string' || plan.dueAt.length === 0) return false;
  return Date.parse(plan.dueAt) < Date.now();
}

function isDueSoon(plan: any): boolean {
  if (!plan || plan.archived) return false;
  if (plan.status === 'completed' || plan.status === 'cancelled' || plan.status === 'accepted-risk') return false;
  if (typeof plan.dueAt !== 'string' || plan.dueAt.length === 0) return false;
  const due = Date.parse(plan.dueAt);
  if (Number.isNaN(due)) return false;
  const now = Date.now();
  return due >= now && due - now < 1000 * 60 * 60 * 24 * 7; // 7 days
}

export function PlanList({ onExport, onSelectPlan, selectedPlanId }: { onExport: (planId: string) => void; onSelectPlan?: (planId: string) => void; selectedPlanId?: string }) {
  const ctx = useRemediation();
  const [filter, setFilter] = useState<RemediationFilter>('all-active');
  const [createOpen, setCreateOpen] = useState(false);
  const [openPlanId, setOpenPlanId] = useState<string | null>(selectedPlanId || null);

  useEffect(() => {
    if (selectedPlanId) setOpenPlanId(selectedPlanId);
  }, [selectedPlanId]);

  const plans = ctx.state.plans;
  const brokenLedgers = ctx.state.ledgerVerification.perPlan;

  const filtered = useMemo(() => {
    const list = plans.filter((p: any) => {
      if (filter === 'archived') return Boolean(p.archived);
      if (p.archived) return false;
      if (filter === 'all-active') return p.status !== 'completed' && p.status !== 'cancelled' && p.status !== 'accepted-risk';
      if (filter === 'completed') return p.status === 'completed';
      if (filter === 'accepted-risk') return p.status === 'accepted-risk';
      if (filter === 'blocked') return p.status === 'blocked';
      if (filter === 'validation-pending') return p.status === 'validation-pending' || (p.validationStatus === 'pending');
      if (filter === 'overdue') return isOverdue(p);
      if (filter === 'due-soon') return isDueSoon(p);
      if (filter === 'broken-ledger') {
        const v = brokenLedgers[p.planId];
        return v && !v.ok;
      }
      return true;
    });
    list.sort((a: any, b: any) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return list;
  }, [plans, filter, brokenLedgers]);

  return (
    <div className="space-y-2" data-testid="plan-list">
      <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="Plan filters">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            role="tab"
            aria-selected={filter === f.id}
            onClick={() => setFilter(f.id)}
            className={[
              'focus-ring rounded-md border px-2 py-1 text-[10px]',
              filter === f.id
                ? 'border-radar-accent/40 bg-radar-accent/10 text-radar-accent'
                : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
            ].join(' ')}
            data-testid={`plan-filter-${f.id}`}
          >
            {f.label}
          </button>
        ))}
        <span className="ml-auto inline-flex items-center gap-1">
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-2 py-1 text-[10px] text-radar-panel"
            data-testid="plan-list-new"
          >
            New plan
          </button>
        </span>
      </div>
      <p className="text-[10px] text-radar-dim" data-testid="plan-list-count">
        Showing {filtered.length} of {plans.length} plan{plans.length === 1 ? '' : 's'}.
      </p>
      {filtered.length === 0 ? (
        <p className="rounded-md border border-dashed border-radar-border bg-radar-panel2/30 px-3 py-3 text-center text-[11px] text-radar-dim" data-testid="plan-list-empty">
          No plans match the current filter.
        </p>
      ) : (
        <ul className="space-y-1">
          {filtered.map((p: any) => (
            <li key={p.planId} className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px]">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <button
                    type="button"
                    onClick={() => { setOpenPlanId(p.planId); if (onSelectPlan) onSelectPlan(p.planId); }}
                    className="focus-ring block w-full truncate text-left text-radar-text hover:underline"
                    data-testid={`plan-list-item-${p.planId}`}
                  >
                    {p.title}
                  </button>
                  <p className="text-[10px] text-radar-dim">
                    {p.status} · {p.localPriority} · {p.ownerLabel || 'no owner'}
                    {p.dueAt ? ` · due ${p.dueAt.slice(0, 10)}` : ''}
                    {isOverdue(p) ? ' · overdue' : ''}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  {brokenLedgers[p.planId] && !brokenLedgers[p.planId].ok && (
                    <span className="rounded-md border border-radar-warn/40 bg-radar-warn/10 px-1.5 py-0.5 text-[10px] text-radar-warn" data-testid={`plan-list-broken-${p.planId}`}>ledger broken</span>
                  )}
                  <button
                    type="button"
                    onClick={() => onExport(p.planId)}
                    className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40"
                    data-testid={`plan-list-export-${p.planId}`}
                  >
                    Export
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}

      {createOpen && (
        <PlanDialog
          open={createOpen}
          mode="create"
          onClose={() => setCreateOpen(false)}
          onSubmit={(args) => ctx.createPlan(args).then((r) => r.ok ? r : Promise.reject(r))}
        />
      )}

      {openPlanId && (
        <PlanDetail planId={openPlanId} onClose={() => setOpenPlanId(null)} onExport={onExport} />
      )}
    </div>
  );
}
