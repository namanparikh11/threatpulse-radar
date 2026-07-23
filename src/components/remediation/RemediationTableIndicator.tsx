/**
 * V6.7 — Local remediation table indicator.
 *
 * Compact status pill rendered inside the existing
 * "Local" column area of the vulnerability table.
 * Shows the most actionable local plan status for a
 * given CVE id. Tooltip-only, no separate large
 * column added to the public table.
 */
import { useMemo } from 'react';
import { useRemediation } from '../../state/RemediationContext';

interface RemediationTableIndicatorProps {
  cveId: string;
}

const TONE: Record<string, string> = {
  draft: 'border-radar-border bg-radar-panel2/40 text-radar-muted',
  planned: 'border-radar-accent/40 bg-radar-accent/10 text-radar-accent',
  'in-progress': 'border-radar-accent2/40 bg-radar-accent2/10 text-radar-accent2',
  blocked: 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn',
  'validation-pending': 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn',
  completed: 'border-radar-accent2/40 bg-radar-accent2/10 text-radar-accent2',
  'accepted-risk': 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn',
  deferred: 'border-radar-border bg-radar-panel2/40 text-radar-muted',
  cancelled: 'border-radar-border bg-radar-panel2/40 text-radar-dim',
};

export function RemediationTableIndicator({ cveId }: RemediationTableIndicatorProps) {
  const ctx = useRemediation();
  const plan = useMemo(() => {
    const all = (ctx.state.plans || []) as any[];
    const linked = all.filter((p) => Array.isArray(p.linkedCveIds) && p.linkedCveIds.includes(cveId));
    if (linked.length === 0) return null;
    const active = linked.find((p) => !p.archived && p.status !== 'completed' && p.status !== 'cancelled' && p.status !== 'accepted-risk');
    return active || linked[0];
  }, [ctx.state.plans, cveId]);

  if (!plan) return null;
  const tone = TONE[plan.status] || TONE.draft;
  const tip = `Local remediation: ${plan.status}${plan.dueAt ? ' · due ' + String(plan.dueAt).slice(0, 10) : ''} · workflow statement only`;
  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] ${tone}`}
      title={tip}
      aria-label={tip}
      data-testid={`remediation-table-indicator-${cveId}`}
    >
      {plan.status}
    </span>
  );
}
