/**
 * V6.7 — Task create / edit dialog.
 */
import { useEffect, useState } from 'react';
import { REMEDIATION_LIMITS, TASK_STATUSES } from '../../remediation/schema.mjs';

interface TaskDialogProps {
  open: boolean;
  mode: 'create' | 'edit';
  planId: string;
  initial?: any;
  order?: number;
  actorLabel?: string;
  onClose(): void;
  onSubmit(args: any): Promise<{ ok: true; task: any; eventId: string } | { ok: false; reason: string }>;
}

export function TaskDialog({ open, mode, planId, initial, order, actorLabel, onClose, onSubmit }: TaskDialogProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [status, setStatus] = useState('todo');
  const [ownerLabel, setOwnerLabel] = useState('');
  const [dueAt, setDueAt] = useState('');
  const [blockerReason, setBlockerReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const t = initial || {};
    setTitle(typeof t.title === 'string' ? t.title : '');
    setDescription(typeof t.description === 'string' ? t.description : '');
    setStatus(TASK_STATUSES.includes(t.status) ? t.status : 'todo');
    setOwnerLabel(typeof t.ownerLabel === 'string' ? t.ownerLabel : '');
    setDueAt(typeof t.dueAt === 'string' ? t.dueAt.slice(0, 10) : '');
    setBlockerReason(typeof t.blockerReason === 'string' ? t.blockerReason : '');
    setError(null);
    setBusy(false);
  }, [open, initial]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const submit = async () => {
    setBusy(true);
    setError(null);
    const args: any = mode === 'create' ? {
      planId,
      title: title.trim().slice(0, REMEDIATION_LIMITS.MAX_TASK_TITLE_CHARS),
      description: description.slice(0, REMEDIATION_LIMITS.MAX_TASK_DESCRIPTION_CHARS),
      status,
      ownerLabel: ownerLabel.slice(0, REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS),
      dueAt: dueAt ? new Date(dueAt).toISOString() : null,
      order: typeof order === 'number' ? order : undefined,
      blockerReason: blockerReason.slice(0, REMEDIATION_LIMITS.MAX_BLOCKER_REASON_CHARS),
      actorLabel: actorLabel || '',
    } : {
      title: title.trim().slice(0, REMEDIATION_LIMITS.MAX_TASK_TITLE_CHARS),
      description: description.slice(0, REMEDIATION_LIMITS.MAX_TASK_DESCRIPTION_CHARS),
      status,
      ownerLabel: ownerLabel.slice(0, REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS),
      dueAt: dueAt ? new Date(dueAt).toISOString() : null,
      blockerReason: blockerReason.slice(0, REMEDIATION_LIMITS.MAX_BLOCKER_REASON_CHARS),
    };
    const r = await onSubmit(args);
    setBusy(false);
    if (!r.ok) {
      setError(r.reason || 'submit-failed');
      return;
    }
    onClose();
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={mode === 'create' ? 'Create remediation task' : 'Edit remediation task'}
      className="fixed inset-0 z-40 flex items-center justify-center bg-radar-bg/70 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="panel max-w-xl w-full max-h-[90vh] overflow-y-auto p-4 space-y-3 text-[12px]" role="document">
        <h2 className="text-sm font-semibold text-radar-text">
          {mode === 'create' ? 'Add remediation task' : 'Edit remediation task'}
        </h2>
        <p className="text-[11px] text-radar-muted">
          Tasks are local workflow records. Completing every task does not auto-complete the plan.
        </p>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Title</span>
          <input
            type="text"
            value={title}
            maxLength={REMEDIATION_LIMITS.MAX_TASK_TITLE_CHARS}
            onChange={(e) => setTitle(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Task title"
            data-testid="task-dialog-title"
          />
        </label>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Description</span>
          <textarea
            value={description}
            maxLength={REMEDIATION_LIMITS.MAX_TASK_DESCRIPTION_CHARS}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Task description"
            data-testid="task-dialog-description"
          />
        </label>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <label className="block">
            <span className="text-[10px] text-radar-muted">Local task status</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="task-dialog-status">
              {TASK_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">User-assigned owner label</span>
            <input
              type="text"
              value={ownerLabel}
              maxLength={REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS}
              onChange={(e) => setOwnerLabel(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
              aria-label="Task owner"
              data-testid="task-dialog-owner"
            />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Local due date</span>
            <input
              type="date"
              value={dueAt}
              onChange={(e) => setDueAt(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
              aria-label="Task due date"
              data-testid="task-dialog-due"
            />
          </label>
        </div>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Blocker reason (local)</span>
          <textarea
            value={blockerReason}
            maxLength={REMEDIATION_LIMITS.MAX_BLOCKER_REASON_CHARS}
            onChange={(e) => setBlockerReason(e.target.value)}
            rows={2}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Blocker reason"
            data-testid="task-dialog-blocker"
          />
        </label>
        {error && (
          <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn">
            {error}
          </p>
        )}
        <div className="flex items-center justify-end gap-2 border-t border-radar-border/40 pt-3">
          <button type="button" onClick={onClose} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text">
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={busy || title.trim().length === 0}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50"
            data-testid="task-dialog-save"
          >
            {busy ? 'Saving…' : mode === 'create' ? 'Add task' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
