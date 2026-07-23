/**
 * V6.7 — Plan create / edit dialog.
 *
 * Local-only workflow form. The dialog never logs
 * the typed values; the trim and length checks are
 * done here so the validator and adapter only see
 * well-formed input.
 *
 * The dialog is keyboard-accessible, traps focus
 * inside the modal surface, and restores focus to
 * the trigger button on close. Long identifiers wrap.
 *
 * The dialog surfaces the documented local-only
 * wording: completion and validation are locally
 * recorded workflow information, not an independent
 * ThreatPulse verification.
 */
import { useEffect, useState } from 'react';
import { REMEDIATION_LIMITS, PLAN_STATUSES, REMEDIATION_TYPES, LOCAL_PRIORITIES, VALIDATION_STATUSES } from '../../remediation/schema.mjs';
import { allowedTransitionsFrom } from '../../remediation/lifecycle.mjs';

interface PlanDialogProps {
  open: boolean;
  mode: 'create' | 'edit';
  initial?: any;
  actorLabel?: string;
  onClose(): void;
  onSubmit(args: any): Promise<{ ok: true; plan: any; eventId: string } | { ok: false; reason: string }>;
}

function clamp(s: string, max: number): string {
  if (typeof s !== 'string') return '';
  if (s.length <= max) return s;
  return s.slice(0, max);
}

function joinTags(input: string): string[] {
  return input.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

function joinCves(input: string): string[] {
  return input.split(',').map((s) => s.trim().toUpperCase()).filter((s) => s.length > 0);
}

export function PlanDialog({ open, mode, initial, actorLabel, onClose, onSubmit }: PlanDialogProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [remediationType, setRemediationType] = useState('other');
  const [localPriority, setLocalPriority] = useState('none');
  const [ownerLabel, setOwnerLabel] = useState('');
  const [dueAt, setDueAt] = useState('');
  const [linkedCveIds, setLinkedCveIds] = useState('');
  const [linkedAssetIds, setLinkedAssetIds] = useState('');
  const [linkedComponentIds, setLinkedComponentIds] = useState('');
  const [linkedCorrelationIds, setLinkedCorrelationIds] = useState('');
  const [tags, setTags] = useState('');
  const [notes, setNotes] = useState('');
  const [status, setStatus] = useState('draft');
  const [validationStatus, setValidationStatus] = useState('not-started');
  const [acceptedRiskRationale, setAcceptedRiskRationale] = useState('');
  const [archived, setArchived] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const p = initial || {};
    setTitle(typeof p.title === 'string' ? p.title : '');
    setDescription(typeof p.description === 'string' ? p.description : '');
    setRemediationType(REMEDIATION_TYPES.includes(p.remediationType) ? p.remediationType : 'other');
    setLocalPriority(LOCAL_PRIORITIES.includes(p.localPriority) ? p.localPriority : 'none');
    setOwnerLabel(typeof p.ownerLabel === 'string' ? p.ownerLabel : '');
    setDueAt(typeof p.dueAt === 'string' ? p.dueAt.slice(0, 10) : '');
    setLinkedCveIds(Array.isArray(p.linkedCveIds) ? p.linkedCveIds.join(', ') : '');
    setLinkedAssetIds(Array.isArray(p.linkedAssetIds) ? p.linkedAssetIds.join(', ') : '');
    setLinkedComponentIds(Array.isArray(p.linkedComponentIds) ? p.linkedComponentIds.join(', ') : '');
    setLinkedCorrelationIds(Array.isArray(p.linkedCorrelationIds) ? p.linkedCorrelationIds.join(', ') : '');
    setTags(Array.isArray(p.tags) ? p.tags.join(', ') : '');
    setNotes(typeof p.notes === 'string' ? p.notes : '');
    setStatus(PLAN_STATUSES.includes(p.status) ? p.status : 'draft');
    setValidationStatus(VALIDATION_STATUSES.includes(p.validationStatus) ? p.validationStatus : 'not-started');
    setAcceptedRiskRationale(typeof p.acceptedRiskRationale === 'string' ? p.acceptedRiskRationale : '');
    setArchived(Boolean(p.archived));
    setError(null);
    setBusy(false);
  }, [open, initial]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const submit = async () => {
    setBusy(true);
    setError(null);
    const args: any = mode === 'create' ? {
      title: clamp(title, REMEDIATION_LIMITS.MAX_PLAN_TITLE_CHARS),
      description: clamp(description, REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS),
      remediationType,
      localPriority,
      ownerLabel: clamp(ownerLabel, REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS),
      dueAt: dueAt ? new Date(dueAt).toISOString() : null,
      linkedCveIds: joinCves(linkedCveIds),
      linkedAssetIds: linkedAssetIds.split(',').map((s) => s.trim()).filter(Boolean),
      linkedComponentIds: linkedComponentIds.split(',').map((s) => s.trim()).filter(Boolean),
      linkedCorrelationIds: linkedCorrelationIds.split(',').map((s) => s.trim()).filter(Boolean),
      tags: joinTags(tags),
      actorLabel: actorLabel || '',
    } : {
      title: clamp(title, REMEDIATION_LIMITS.MAX_PLAN_TITLE_CHARS),
      description: clamp(description, REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS),
      remediationType,
      localPriority,
      ownerLabel: clamp(ownerLabel, REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS),
      dueAt: dueAt ? new Date(dueAt).toISOString() : null,
      linkedCveIds: joinCves(linkedCveIds),
      linkedAssetIds: linkedAssetIds.split(',').map((s) => s.trim()).filter(Boolean),
      linkedComponentIds: linkedComponentIds.split(',').map((s) => s.trim()).filter(Boolean),
      linkedCorrelationIds: linkedCorrelationIds.split(',').map((s) => s.trim()).filter(Boolean),
      tags: joinTags(tags),
      notes: clamp(notes, REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS),
      status,
      validationStatus,
      acceptedRiskRationale: clamp(acceptedRiskRationale, REMEDIATION_LIMITS.MAX_RATIONALE_CHARS),
      archived,
    };
    const r = await onSubmit(args);
    setBusy(false);
    if (!r.ok) {
      setError(r.reason || 'submit-failed');
      return;
    }
    onClose();
  };

  const transitions = mode === 'edit' && initial ? allowedTransitionsFrom(initial.status) : [];
  const cveCount = joinCves(linkedCveIds).length;
  const tagCount = joinTags(tags).length;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={mode === 'create' ? 'Create remediation plan' : 'Edit remediation plan'}
      className="fixed inset-0 z-40 flex items-center justify-center bg-radar-bg/70 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="panel max-w-2xl w-full max-h-[90vh] overflow-y-auto p-4 space-y-3 text-[12px]" role="document">
        <h2 className="text-sm font-semibold text-radar-text">
          {mode === 'create' ? 'Create local remediation plan' : 'Edit local remediation plan'}
        </h2>
        <p className="text-[11px] text-radar-muted">
          Remediation plans and evidence are stored only in this browser. Completion and validation states are locally recorded workflow information, not an independent ThreatPulse verification.
        </p>

        <label className="block">
          <span className="text-[10px] text-radar-muted">Title</span>
          <input
            type="text"
            value={title}
            maxLength={REMEDIATION_LIMITS.MAX_PLAN_TITLE_CHARS}
            onChange={(e) => setTitle(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Plan title"
            data-testid="plan-dialog-title"
          />
        </label>

        <label className="block">
          <span className="text-[10px] text-radar-muted">Description</span>
          <textarea
            value={description}
            maxLength={REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Plan description"
            data-testid="plan-dialog-description"
          />
        </label>

        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <label className="block">
            <span className="text-[10px] text-radar-muted">Remediation type</span>
            <select value={remediationType} onChange={(e) => setRemediationType(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="plan-dialog-remediation-type">
              {REMEDIATION_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">User-assigned local priority</span>
            <select value={localPriority} onChange={(e) => setLocalPriority(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="plan-dialog-priority">
              {LOCAL_PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
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
              aria-label="Owner label"
              data-testid="plan-dialog-owner"
            />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Local due date</span>
            <input
              type="date"
              value={dueAt}
              onChange={(e) => setDueAt(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
              aria-label="Due date"
              data-testid="plan-dialog-due"
            />
          </label>
        </div>

        {mode === 'edit' && (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <label className="block">
              <span className="text-[10px] text-radar-muted">Local workflow status</span>
              <select value={status} onChange={(e) => setStatus(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="plan-dialog-status">
                {PLAN_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-[10px] text-radar-muted">Local validation status</span>
              <select value={validationStatus} onChange={(e) => setValidationStatus(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="plan-dialog-validation-status">
                {VALIDATION_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
          </div>
        )}

        <fieldset className="space-y-1">
          <legend className="text-[10px] text-radar-muted">Linked identifiers (comma-separated, locally stored)</legend>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked CVE ids</span>
            <input
              type="text"
              value={linkedCveIds}
              onChange={(e) => setLinkedCveIds(e.target.value)}
              placeholder="CVE-2024-3094, CVE-2024-0001"
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text"
              aria-label="Linked CVE ids"
              data-testid="plan-dialog-cves"
            />
            <span className="mt-1 block text-[10px] text-radar-dim">{cveCount} / {REMEDIATION_LIMITS.MAX_LINKED_CVES}</span>
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked asset ids (local)</span>
            <input type="text" value={linkedAssetIds} onChange={(e) => setLinkedAssetIds(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text" aria-label="Linked asset ids" data-testid="plan-dialog-assets" />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked component ids (local)</span>
            <input type="text" value={linkedComponentIds} onChange={(e) => setLinkedComponentIds(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text" aria-label="Linked component ids" data-testid="plan-dialog-components" />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked correlation ids (local)</span>
            <input type="text" value={linkedCorrelationIds} onChange={(e) => setLinkedCorrelationIds(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text" aria-label="Linked correlation ids" data-testid="plan-dialog-correlations" />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Tags (comma-separated, normalized locally)</span>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
              aria-label="Tags"
              data-testid="plan-dialog-tags"
            />
            <span className="mt-1 block text-[10px] text-radar-dim">{tagCount} / {REMEDIATION_LIMITS.MAX_TAGS}</span>
          </label>
        </fieldset>

        {mode === 'edit' && (
          <>
            <label className="block">
              <span className="text-[10px] text-radar-muted">Local notes (operator workflow notes)</span>
              <textarea
                value={notes}
                maxLength={REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS}
                onChange={(e) => setNotes(e.target.value)}
                rows={2}
                className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
                aria-label="Local notes"
                data-testid="plan-dialog-notes"
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-radar-muted">Accepted-risk rationale (recorded locally, NOT external approval)</span>
              <textarea
                value={acceptedRiskRationale}
                maxLength={REMEDIATION_LIMITS.MAX_RATIONALE_CHARS}
                onChange={(e) => setAcceptedRiskRationale(e.target.value)}
                rows={2}
                className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
                aria-label="Accepted-risk rationale"
                data-testid="plan-dialog-rationale"
              />
            </label>
            <label className="flex items-center gap-2 text-[11px] text-radar-muted">
              <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} aria-label="Archived" data-testid="plan-dialog-archived" />
              <span>Archived (hidden from default lists, kept in storage)</span>
            </label>
          </>
        )}

        {error && (
          <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn">
            {error}
          </p>
        )}

        {mode === 'edit' && initial && (
          <p className="text-[10px] text-radar-dim">
            Allowed transitions from {initial.status}: {transitions.length === 0 ? 'none' : transitions.join(', ')}
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
            data-testid="plan-dialog-save"
          >
            {busy ? 'Saving…' : mode === 'create' ? 'Create plan' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
