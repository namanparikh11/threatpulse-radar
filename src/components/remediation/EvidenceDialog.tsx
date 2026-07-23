/**
 * V6.7 — Evidence create / edit dialog.
 */
import { useEffect, useState } from 'react';
import { REMEDIATION_LIMITS, EVIDENCE_TYPES, EVIDENCE_VALIDATION_OUTCOMES } from '../../remediation/schema.mjs';

interface EvidenceDialogProps {
  open: boolean;
  mode: 'create' | 'edit' | 'supersede';
  planId: string;
  taskId?: string | null;
  initial?: any;
  actorLabel?: string;
  onClose(): void;
  onSubmit(args: any): Promise<{ ok: true; evidence: any; eventId: string } | { ok: false; reason: string }>;
}

export function EvidenceDialog({ open, mode, planId, taskId, initial, actorLabel, onClose, onSubmit }: EvidenceDialogProps) {
  const [evidenceType, setEvidenceType] = useState('local-note');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [sourceLabel, setSourceLabel] = useState('');
  const [externalUrl, setExternalUrl] = useState('');
  const [linkedInventoryId, setLinkedInventoryId] = useState('');
  const [linkedCorrelationId, setLinkedCorrelationId] = useState('');
  const [linkedReportId, setLinkedReportId] = useState('');
  const [validationOutcome, setValidationOutcome] = useState('');
  const [fileFingerprint, setFileFingerprint] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const e = initial || {};
    setEvidenceType(EVIDENCE_TYPES.includes(e.evidenceType) ? e.evidenceType : 'local-note');
    setTitle(typeof e.title === 'string' ? e.title : '');
    setDescription(typeof e.description === 'string' ? e.description : '');
    setSourceLabel(typeof e.sourceLabel === 'string' ? e.sourceLabel : '');
    setExternalUrl(typeof e.externalUrl === 'string' ? e.externalUrl : '');
    setLinkedInventoryId(typeof e.linkedInventoryId === 'string' ? e.linkedInventoryId : '');
    setLinkedCorrelationId(typeof e.linkedCorrelationId === 'string' ? e.linkedCorrelationId : '');
    setLinkedReportId(typeof e.linkedReportId === 'string' ? e.linkedReportId : '');
    setValidationOutcome(typeof e.validationOutcome === 'string' ? e.validationOutcome : '');
    setFileFingerprint(e.fileFingerprint || null);
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
    const args: any = {
      planId,
      taskId: taskId || null,
      evidenceType,
      title: title.trim().slice(0, REMEDIATION_LIMITS.MAX_EVIDENCE_TITLE_CHARS),
      description: description.slice(0, REMEDIATION_LIMITS.MAX_EVIDENCE_DESCRIPTION_CHARS),
      sourceLabel: sourceLabel.slice(0, REMEDIATION_LIMITS.MAX_SOURCE_LABEL_CHARS),
      externalUrl: externalUrl.trim() || null,
      linkedInventoryId: linkedInventoryId.trim() || null,
      linkedCorrelationId: linkedCorrelationId.trim() || null,
      linkedReportId: linkedReportId.trim() || null,
      fileFingerprint: fileFingerprint || null,
      validationOutcome: validationOutcome || null,
      actorLabel: actorLabel || '',
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
      aria-label={mode === 'supersede' ? 'Supersede evidence' : 'Add evidence'}
      className="fixed inset-0 z-40 flex items-center justify-center bg-radar-bg/70 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="panel max-w-xl w-full max-h-[90vh] overflow-y-auto p-4 space-y-3 text-[12px]" role="document">
        <h2 className="text-sm font-semibold text-radar-text">
          {mode === 'supersede' ? 'Supersede evidence (record a correction)' : 'Add local evidence'}
        </h2>
        <p className="text-[11px] text-radar-muted">
          Evidence files stay on the device. The dialog never uploads content. The recorded fingerprint
          is only the file name, size, MIME type, lastModified, and SHA-256 checksum.
        </p>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Evidence type</span>
          <select value={evidenceType} onChange={(e) => setEvidenceType(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="evidence-dialog-type">
            {EVIDENCE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Title</span>
          <input
            type="text"
            value={title}
            maxLength={REMEDIATION_LIMITS.MAX_EVIDENCE_TITLE_CHARS}
            onChange={(e) => setTitle(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Evidence title"
            data-testid="evidence-dialog-title"
          />
        </label>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Description</span>
          <textarea
            value={description}
            maxLength={REMEDIATION_LIMITS.MAX_EVIDENCE_DESCRIPTION_CHARS}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Evidence description"
            data-testid="evidence-dialog-description"
          />
        </label>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <label className="block">
            <span className="text-[10px] text-radar-muted">Source label</span>
            <input
              type="text"
              value={sourceLabel}
              maxLength={REMEDIATION_LIMITS.MAX_SOURCE_LABEL_CHARS}
              onChange={(e) => setSourceLabel(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
              aria-label="Source label"
              data-testid="evidence-dialog-source"
            />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Local validation outcome (optional)</span>
            <select value={validationOutcome} onChange={(e) => setValidationOutcome(e.target.value)} className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text" data-testid="evidence-dialog-validation-outcome">
              <option value="">(none)</option>
              {EVIDENCE_VALIDATION_OUTCOMES.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
        </div>
        <label className="block">
          <span className="text-[10px] text-radar-muted">External URL (https only, optional, NEVER auto-fetched)</span>
          <input
            type="url"
            value={externalUrl}
            maxLength={REMEDIATION_LIMITS.MAX_EXTERNAL_URL_CHARS}
            onChange={(e) => setExternalUrl(e.target.value)}
            placeholder="https://example.com/issue/123"
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="External URL"
            data-testid="evidence-dialog-url"
          />
        </label>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked inventory id</span>
            <input
              type="text"
              value={linkedInventoryId}
              onChange={(e) => setLinkedInventoryId(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text"
              aria-label="Linked inventory id"
              data-testid="evidence-dialog-inventory"
            />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked correlation id</span>
            <input
              type="text"
              value={linkedCorrelationId}
              onChange={(e) => setLinkedCorrelationId(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text"
              aria-label="Linked correlation id"
              data-testid="evidence-dialog-correlation"
            />
          </label>
          <label className="block">
            <span className="text-[10px] text-radar-muted">Linked report id</span>
            <input
              type="text"
              value={linkedReportId}
              onChange={(e) => setLinkedReportId(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] font-mono text-radar-text"
              aria-label="Linked report id"
              data-testid="evidence-dialog-report"
            />
          </label>
        </div>
        {fileFingerprint && (
          <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2 text-[11px] text-radar-text" data-testid="evidence-dialog-fingerprint">
            <p className="font-mono break-all">{fileFingerprint.checksum}</p>
            <p className="text-radar-dim">{fileFingerprint.fileName} · {fileFingerprint.sizeBytes} bytes · {fileFingerprint.mimeType || 'unknown mime'}</p>
          </div>
        )}
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
            data-testid="evidence-dialog-save"
          >
            {busy ? 'Saving…' : mode === 'supersede' ? 'Record correction' : 'Add evidence'}
          </button>
        </div>
      </div>
    </div>
  );
}
