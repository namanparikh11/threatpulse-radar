/**
 * V6.7 — Local remediation drawer section.
 *
 * Compact surface inside the CVE detail drawer. Shows
 * the count of local remediation plans that reference
 * this CVE, the active plan status (if any), and the
 * document entry points (create plan, open plan).
 *
 * The section never logs private data, never writes to
 * the URL, and never claims the recorded completion is
 * an external verification.
 */
import { useMemo, useState } from 'react';
import { useRemediation } from '../../state/RemediationContext';
import { PlanDialog } from './PlanDialog';
import { PlanDetail } from './PlanDetail';

interface RemediationDrawerSectionProps {
  cveId: string;
}

export function RemediationDrawerSection({ cveId }: RemediationDrawerSectionProps) {
  const ctx = useRemediation();
  const [createOpen, setCreateOpen] = useState(false);
  const [openPlanId, setOpenPlanId] = useState<string | null>(null);

  const linked = useMemo(
    () => (ctx.state.plans || []).filter((p: any) => Array.isArray(p.linkedCveIds) && p.linkedCveIds.includes(cveId)),
    [ctx.state.plans, cveId],
  );

  const active = useMemo(
    () => linked.find((p: any) => !p.archived && p.status !== 'completed' && p.status !== 'cancelled' && p.status !== 'accepted-risk') || null,
    [linked],
  );

  const statusLabel = active
    ? `${active.status}${active.localPriority && active.localPriority !== 'none' ? ' · ' + active.localPriority : ''}${active.dueAt ? ' · due ' + String(active.dueAt).slice(0, 10) : ''}`
    : 'No active local plan';

  return (
    <section className="rounded-md border border-radar-border bg-radar-panel2/40 p-2 text-[11px]" aria-label="Local remediation">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-[10px] font-medium text-radar-muted">Local remediation</p>
          <p className="text-radar-text" data-testid="remediation-drawer-status">
            {statusLabel}
          </p>
          <p className="text-[10px] text-radar-dim">
            {linked.length} linked plan{linked.length === 1 ? '' : 's'} · locally stored workflow data only
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2 py-0.5 text-[10px] text-radar-accent"
            data-testid="remediation-drawer-create"
          >
            Create plan
          </button>
          {active && (
            <button
              type="button"
              onClick={() => setOpenPlanId(active.planId)}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid="remediation-drawer-open"
            >
              Open plan
            </button>
          )}
        </div>
      </div>
      {createOpen && (
        <PlanDialog
          open={createOpen}
          mode="create"
          onClose={() => setCreateOpen(false)}
          onSubmit={async (args: any) => {
            const r = await ctx.createPlan({ ...args, linkedCveIds: [cveId] });
            if (r.ok) {
              setCreateOpen(false);
              setOpenPlanId(r.plan.planId);
            }
            return r;
          }}
        />
      )}
      {openPlanId && (
        <div className="mt-2">
          <PlanDetail
            planId={openPlanId}
            onClose={() => setOpenPlanId(null)}
            onExport={async () => {
              // Wired in commit 7 (bundle export).
            }}
          />
        </div>
      )}
    </section>
  );
}
