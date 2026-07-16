/**
 * V6.6 — Correlation review dialog.
 *
 * The operator marks a correlation as one of the
 * documented review statuses (unreviewed / confirmed-
 * relevant / dismissed / needs-validation / etc.)
 * and may attach a short private note. The save
 * action goes through the EnvironmentContext which
 * applies the V6.4-style revision + mutationId
 * conflict rules.
 *
 * The dialog is presentation-only; it never touches
 * the network, the URL, or the console.
 */

import { useState } from 'react';
import { useEnvironment } from '../../state/EnvironmentContext';
import { REVIEW_STATUSES, ASSET_LIMITS } from '../../environment/schema.mjs';
import ReportDialogShell from '../reports/ReportDialogShell';

export interface CorrelationReviewDialogProps {
  correlation: any;
  onClose: () => void;
}

const STATUS_LABEL: Record<string, string> = {
  'unreviewed': 'Unreviewed',
  'confirmed-relevant': 'Confirmed relevant',
  'dismissed': 'Dismissed',
  'needs-validation': 'Needs validation',
  'remediation-planned': 'Remediation planned',
  'remediation-in-progress': 'Remediation in progress',
  'remediated': 'Remediated (local statement only)',
  'accepted-risk': 'Accepted risk',
};

export default function CorrelationReviewDialog({ correlation, onClose }: CorrelationReviewDialogProps) {
  const env = useEnvironment();
  const existing = (env.state.reviewsByCorrelation && env.state.reviewsByCorrelation[correlation.correlationId]) || null;
  const [status, setStatus] = useState(existing ? existing.reviewStatus : 'unreviewed');
  const [note, setNote] = useState(existing ? existing.note : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSave = async () => {
    setBusy(true);
    setError(null);
    const r = await env.saveReview(correlation.correlationId, status, note);
    if (!r.ok) setError(r.reason);
    else onClose();
    setBusy(false);
  };

  return (
    <ReportDialogShell title={`Review ${correlation.cveId} (${correlation.assetName})`} onClose={onClose}>
      <p className="text-[11px] text-radar-muted" data-testid="review-correlation-preamble">
        Review status and notes are user-authored local workflow information. They do not change the underlying provider evidence and are never uploaded.
      </p>
      <div className="mt-3 grid grid-cols-1 gap-2">
        <label className="block">
          <span className="text-[11px] text-radar-muted">Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            data-testid="review-status"
          >
            {REVIEW_STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s] || s}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Note (local-only)</span>
          <textarea
            value={note}
            maxLength={ASSET_LIMITS.MAX_REVIEW_NOTE_CHARS}
            onChange={(e) => setNote(e.target.value)}
            rows={4}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            data-testid="review-note"
          />
          <span className="mt-1 block text-[10px] text-radar-dim">{note.length} / {ASSET_LIMITS.MAX_REVIEW_NOTE_CHARS}</span>
        </label>
      </div>
      {error && (
        <p role="alert" aria-live="polite" className="mt-3 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn">{error}</p>
      )}
      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={busy}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50"
          data-testid="review-save"
        >
          {busy ? 'Saving…' : 'Save review'}
        </button>
      </div>
    </ReportDialogShell>
  );
}
