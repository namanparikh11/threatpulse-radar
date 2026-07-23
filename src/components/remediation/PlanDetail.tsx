/**
 * V6.7 — Plan detail panel.
 *
 * Shows the full plan, its tasks, evidence, and the
 * append-only ledger timeline. Inline action buttons
 * drive the documented state transitions. The panel
 * surfaces the validated transition list so the
 * operator can never click an invalid button.
 */
import { useEffect, useMemo, useState } from 'react';
import { useRemediation } from '../../state/RemediationContext';
import { REMEDIATION_LIMITS } from '../../remediation/schema.mjs';
import { allowedTransitionsFrom, isSupportedTransition } from '../../remediation/lifecycle.mjs';
import { TaskDialog } from './TaskDialog';
import { EvidenceDialog } from './EvidenceDialog';
import { FingerprintDialog } from './FingerprintDialog';
import { verifyChain } from '../../remediation/ledger.mjs';

interface PlanDetailProps {
  planId: string;
  onClose(): void;
  onExport(planId: string): void;
}

function fmtTime(iso: string | null | undefined): string {
  if (typeof iso !== 'string' || iso.length === 0) return '—';
  return iso.replace('T', ' ').replace(/\..+/, '').replace('Z', ' UTC');
}

function isOverdue(plan: any): boolean {
  if (!plan || plan.archived) return false;
  if (plan.status === 'completed' || plan.status === 'cancelled' || plan.status === 'accepted-risk') return false;
  if (typeof plan.dueAt !== 'string' || plan.dueAt.length === 0) return false;
  return Date.parse(plan.dueAt) < Date.now();
}

export function PlanDetail({ planId, onClose, onExport }: PlanDetailProps) {
  const ctx = useRemediation();
  const plan = ctx.state.plans.find((p) => p.planId === planId) || null;
  const tasks = ctx.state.tasksByPlan[planId] || [];
  const evidence = ctx.state.evidenceByPlan[planId] || [];
  const events = ctx.state.ledgerByPlan[planId] || [];
  const transitions = useMemo(() => (plan ? allowedTransitionsFrom(plan.status) : []), [plan]);
  const [taskDialog, setTaskDialog] = useState<'closed' | 'create' | 'edit'>('closed');
  const [editingTask, setEditingTask] = useState<any | null>(null);
  const [evidenceDialog, setEvidenceDialog] = useState<'closed' | 'create' | 'supersede'>('closed');
  const [editingEvidence, setEditingEvidence] = useState<any | null>(null);
  const [fingerprintDialog, setFingerprintDialog] = useState<{ open: boolean; initial: any | null; taskId: string | null }>({ open: false, initial: null, taskId: null });
  const [pendingFingerprint, setPendingFingerprint] = useState<any | null>(null);
  const [validationNote, setValidationNote] = useState('');
  const [riskRationale, setRiskRationale] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [verifyState, setVerifyState] = useState<{ ok: boolean; reason?: string; eventCount?: number } | null>(null);

  useEffect(() => {
    if (!planId) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await verifyChain(events);
        if (!cancelled) setVerifyState(r);
      } catch (err: any) {
        if (!cancelled) setVerifyState({ ok: false, reason: err?.message || 'integrity-unavailable' });
      }
    })();
    return () => { cancelled = true; };
  }, [planId, events]);

  if (!plan) {
    return (
      <div className="panel p-4 text-[12px] text-radar-muted" role="region" aria-label="Plan detail">
        <p>Plan not found.</p>
        <button type="button" onClick={onClose} className="mt-2 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted">Close</button>
      </div>
    );
  }

  const onTransition = async (to: string) => {
    setError(null);
    if (!isSupportedTransition(plan.status, to)) {
      setError('unsupported-status-transition');
      return;
    }
    if (to === 'accepted-risk' && !riskRationale.trim()) {
      setError('risk-rationale-required');
      return;
    }
    let r;
    if (to === 'accepted-risk') {
      r = await ctx.acceptRisk(planId, riskRationale.trim(), '');
    } else {
      r = await ctx.setStatus(planId, to, '');
    }
    if (!r.ok) setError(r.reason || 'transition-failed');
    else setRiskRationale('');
  };

  const onValidation = async (toStatus: string) => {
    setError(null);
    const r = await ctx.setValidation(planId, toStatus, validationNote, '');
    if (!r.ok) {
      setError(r.reason || 'validation-failed');
      return;
    }
    setValidationNote('');
  };

  const onCompletePlan = async () => {
    setError(null);
    const r = await ctx.updatePlan(planId, { status: 'completed', completedAt: new Date().toISOString() }, '');
    if (!r.ok) {
      setError(r.reason || 'complete-failed');
      return;
    }
    // Best-effort validation event
    await ctx.setValidation(planId, ctx.state.plans.find((p) => p.planId === planId)?.validationStatus || 'not-started', 'Plan completed locally.', '');
  };

  const onReopen = async () => {
    setError(null);
    const r = await ctx.reopenPlan(planId, '');
    if (!r.ok) setError(r.reason || 'reopen-failed');
  };

  const onDelete = async () => {
    if (typeof window !== 'undefined' && !window.confirm('Delete this plan and its local ledger? This cannot be undone.')) return;
    const r = await ctx.deletePlan(planId);
    if (!r.ok) setError(r.reason || 'delete-failed');
    else onClose();
  };

  const onAddEvidence = async (args: any) => {
    const merged = pendingFingerprint ? { ...args, fileFingerprint: pendingFingerprint } : args;
    if (merged.fileFingerprint) {
      setError(null);
      return ctx.addEvidence({
        ...merged,
        evidenceType: 'local-file-fingerprint',
        fileFingerprint: merged.fileFingerprint,
      });
    }
    return ctx.addEvidence(merged);
  };

  const onSupersedeEvidence = async (args: any) => {
    if (!editingEvidence) return { ok: false as const, reason: 'no-evidence' };
    return ctx.supersedeEvidence(editingEvidence.evidenceId, args, '');
  };

  return (
    <div className="panel space-y-3 p-4 text-[12px]" role="region" aria-label="Plan detail">
      <header className="space-y-1">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h2 className="text-sm font-semibold text-radar-text">{plan.title}</h2>
          <div className="flex flex-wrap items-center gap-1">
            <span className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted" data-testid="plan-detail-status">{plan.status}</span>
            {isOverdue(plan) && <span className="rounded-md border border-radar-warn/40 bg-radar-warn/10 px-2 py-0.5 text-[10px] text-radar-warn" data-testid="plan-detail-overdue">overdue</span>}
            <span className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted" data-testid="plan-detail-priority">{plan.localPriority}</span>
            {plan.archived && <span className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted">archived</span>}
          </div>
        </div>
        <p className="text-[11px] text-radar-muted">
          {plan.description || 'No description.'}
        </p>
        <p className="text-[10px] text-radar-dim">
          Owner: {plan.ownerLabel || '—'} · Created: {fmtTime(plan.createdAt)} · Updated: {fmtTime(plan.updatedAt)} · Due: {fmtTime(plan.dueAt)}
        </p>
        <p className="text-[10px] text-radar-dim">
          Remediation type: {plan.remediationType} · Local validation: {plan.validationStatus}
        </p>
        {plan.linkedCveIds && plan.linkedCveIds.length > 0 && (
          <p className="text-[10px] font-mono text-radar-muted">
            Linked CVEs: {plan.linkedCveIds.join(', ')}
          </p>
        )}
      </header>

      {error && (
        <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="plan-detail-error">
          {error}
        </p>
      )}

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <p className="text-[10px] font-medium text-radar-muted">Local workflow status</p>
        <p className="text-[10px] text-radar-dim">
          Allowed transitions from <span className="font-mono">{plan.status}</span>: {transitions.length === 0 ? 'none' : transitions.join(', ')}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2" data-testid="plan-detail-transitions">
          {transitions.map((to) => (
            <button
              key={to}
              type="button"
              onClick={() => onTransition(to)}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid={`plan-detail-transition-${to}`}
            >
              → {to}
            </button>
          ))}
          {plan.status === 'completed' && (
            <button type="button" onClick={onReopen} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2 py-1 text-[10px] text-radar-accent" data-testid="plan-detail-reopen">
              Reopen
            </button>
          )}
        </div>
        {plan.status !== 'completed' && plan.status !== 'cancelled' && plan.status !== 'accepted-risk' && (
          <div className="mt-2 flex items-center gap-2">
            <button type="button" onClick={onCompletePlan} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-2 py-1 text-[10px] text-radar-panel" data-testid="plan-detail-complete">
              Record as completed locally
            </button>
            <span className="text-[10px] text-radar-dim">Completion is a local workflow statement; external validation has not been performed by ThreatPulse.</span>
          </div>
        )}
      </div>

      {plan.status === 'accepted-risk' && (
        <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2 text-[11px] text-radar-text">
          <p className="text-[10px] font-medium text-radar-muted">Accepted risk rationale (local, NOT external approval)</p>
          <p className="whitespace-pre-wrap">{plan.acceptedRiskRationale || '(none recorded)'}</p>
        </div>
      )}

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <p className="text-[10px] font-medium text-radar-muted">Local validation</p>
        <textarea
          value={validationNote}
          onChange={(e) => setValidationNote(e.target.value)}
          rows={2}
          placeholder="Local validation note (stored only in this browser)"
          className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
          aria-label="Validation note"
          data-testid="plan-detail-validation-note"
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {['passed-locally', 'failed-locally', 'inconclusive', 'not-applicable'].map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => onValidation(v)}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid={`plan-detail-validation-${v}`}
            >
              Record {v}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <p className="text-[10px] font-medium text-radar-muted">Accepted risk (local workflow statement only)</p>
        <textarea
          value={riskRationale}
          onChange={(e) => setRiskRationale(e.target.value)}
          rows={2}
          maxLength={REMEDIATION_LIMITS.MAX_RATIONALE_CHARS}
          placeholder="Local rationale (NOT external approval)"
          className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
          aria-label="Accepted-risk rationale"
          data-testid="plan-detail-risk-rationale"
        />
      </div>

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-medium text-radar-muted">Local tasks ({tasks.length} / {REMEDIATION_LIMITS.MAX_TASKS_PER_PLAN})</p>
          <button
            type="button"
            onClick={() => { setEditingTask(null); setTaskDialog('create'); }}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2 py-1 text-[10px] text-radar-accent"
            data-testid="plan-detail-add-task"
          >
            Add task
          </button>
        </div>
        {tasks.length === 0 ? (
          <p className="mt-2 text-[10px] text-radar-dim">No tasks yet.</p>
        ) : (
          <ul className="mt-2 space-y-1" data-testid="plan-detail-tasks">
            {tasks.map((t: any) => (
              <li key={t.taskId} className="flex items-start justify-between gap-2 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px]">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-radar-text">{t.title}</p>
                  <p className="text-[10px] text-radar-dim">{t.status} · {t.ownerLabel || 'no owner'} · {fmtTime(t.dueAt)}</p>
                  {t.blockerReason && <p className="text-[10px] text-radar-warn">blocker: {t.blockerReason}</p>}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  {t.status !== 'done' && (
                    <button type="button" onClick={() => ctx.completeTask(t.taskId, '')} className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40" data-testid={`task-complete-${t.taskId}`}>
                      Done
                    </button>
                  )}
                  {t.status === 'done' && (
                    <button type="button" onClick={() => ctx.reopenTask(t.taskId, '')} className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40" data-testid={`task-reopen-${t.taskId}`}>
                      Reopen
                    </button>
                  )}
                  <button type="button" onClick={() => { setEditingTask(t); setTaskDialog('edit'); }} className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40" data-testid={`task-edit-${t.taskId}`}>
                    Edit
                  </button>
                  <button type="button" onClick={() => { if (window.confirm('Delete this task locally?')) ctx.deleteTask(t.taskId, ''); }} className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn" data-testid={`task-delete-${t.taskId}`}>
                    Delete
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-medium text-radar-muted">Local evidence ({evidence.length} / {REMEDIATION_LIMITS.MAX_EVIDENCE_PER_PLAN})</p>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => { setEditingEvidence(null); setEvidenceDialog('create'); }}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2 py-1 text-[10px] text-radar-accent"
              data-testid="plan-detail-add-evidence"
            >
              Add evidence
            </button>
            <button
              type="button"
              onClick={() => setFingerprintDialog({ open: true, initial: null, taskId: null })}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid="plan-detail-fingerprint"
            >
              Fingerprint file
            </button>
          </div>
        </div>
        {evidence.length === 0 ? (
          <p className="mt-2 text-[10px] text-radar-dim">No evidence yet.</p>
        ) : (
          <ul className="mt-2 space-y-1" data-testid="plan-detail-evidence">
            {evidence.map((e: any) => (
              <li key={e.evidenceId} className="rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px]">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <p className="text-radar-text">{e.title}</p>
                    <p className="text-[10px] text-radar-dim">{e.evidenceType} · {fmtTime(e.capturedAt)} · {e.sourceLabel || 'no source label'}</p>
                    {e.description && <p className="mt-1 text-[11px] text-radar-muted whitespace-pre-wrap">{e.description}</p>}
                    {e.fileFingerprint && (
                      <p className="mt-1 font-mono text-[10px] text-radar-muted break-all">{e.fileFingerprint.checksum}</p>
                    )}
                    {e.validationOutcome && <p className="text-[10px] text-radar-muted">validation: {e.validationOutcome}</p>}
                    {e.supersedesEvidenceId && <p className="text-[10px] text-radar-dim">supersedes: {e.supersedesEvidenceId}</p>}
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <button
                      type="button"
                      onClick={() => { setEditingEvidence(e); setEvidenceDialog('supersede'); }}
                      className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40"
                      data-testid={`evidence-supersede-${e.evidenceId}`}
                    >
                      Record correction
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2">
        <p className="text-[10px] font-medium text-radar-muted">Local activity timeline (append-only)</p>
        <p className="text-[10px] text-radar-dim" data-testid="plan-detail-ledger-verify">
          Chain integrity: {verifyState === null ? 'verifying…' : verifyState.ok ? `valid (${verifyState.eventCount || 0} events)` : `BROKEN — ${verifyState.reason}`}
        </p>
        {events.length === 0 ? (
          <p className="mt-2 text-[10px] text-radar-dim">No events yet.</p>
        ) : (
          <ol className="mt-2 space-y-1 text-[10px] font-mono text-radar-muted" data-testid="plan-detail-ledger">
            {events.map((ev: any) => (
              <li key={ev.eventId} className="break-words">
                <span className="text-radar-dim">#{ev.sequence}</span> {ev.eventType} · {fmtTime(ev.occurredAt)} · {ev.summary}
              </li>
            ))}
          </ol>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-radar-border/40 pt-3">
        <button type="button" onClick={onClose} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text">
          Close
        </button>
        <button type="button" onClick={() => onExport(planId)} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text" data-testid="plan-detail-export">
          Export plan bundle
        </button>
        <button type="button" onClick={() => { if (window.confirm('Archive this plan? It will be hidden from default lists but its ledger is preserved.')) ctx.archivePlan(planId, ''); }} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn">
          Archive
        </button>
        <button type="button" onClick={onDelete} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-3 py-1.5 text-xs text-radar-warn" data-testid="plan-detail-delete">
          Delete plan + ledger
        </button>
      </div>

      {taskDialog !== 'closed' && (
        <TaskDialog
          open={true}
          mode={taskDialog === 'create' ? 'create' : 'edit'}
          planId={planId}
          initial={editingTask || undefined}
          onClose={() => { setTaskDialog('closed'); setEditingTask(null); }}
          onSubmit={(args) => taskDialog === 'create' ? ctx.addTask(args) : ctx.updateTask(editingTask.taskId, args, '')}
        />
      )}

      {evidenceDialog !== 'closed' && (
        <EvidenceDialog
          open={true}
          mode={evidenceDialog === 'create' ? 'create' : 'supersede'}
          planId={planId}
          initial={editingEvidence || undefined}
          onClose={() => { setEvidenceDialog('closed'); setEditingEvidence(null); }}
          onSubmit={evidenceDialog === 'create' ? onAddEvidence : onSupersedeEvidence}
        />
      )}

      <FingerprintDialog
        open={fingerprintDialog.open}
        initialFingerprint={fingerprintDialog.initial}
        onClose={() => { setFingerprintDialog({ open: false, initial: null, taskId: null }); }}
        onResult={(fp) => {
          setPendingFingerprint(fp);
          setFingerprintDialog({ open: false, initial: fp, taskId: fingerprintDialog.taskId });
          setEditingEvidence(null);
          setEvidenceDialog('create');
        }}
      />
    </div>
  );
}
