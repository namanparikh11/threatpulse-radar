/**
 * V6.8 — Accessible local data clear confirmation.
 *
 * A small, keyboard-accessible dialog that confirms
 * a destructive clear action on a single local
 * dataset. The dialog is required for every clear
 * action exposed by the Local Data Control Centre.
 * The dialog is intentionally dataset-scoped — a
 * clear action on one dataset can never clear
 * another.
 */
import { useEffect, useRef } from 'react';
import { AlertTriangle, ShieldAlert, X } from 'lucide-react';

interface ClearConfirmDialogProps {
  open: boolean;
  kind: 'workspace' | 'environment' | 'remediation' | 'history';
  exportFirst: boolean;
  busy: boolean;
  onCancel(): void;
  onConfirm(): void;
}

const COPY: Record<ClearConfirmDialogProps['kind'], { title: string; description: string; label: string }> = {
  workspace: {
    title: 'Clear local workspace?',
    description: 'This removes every local CVE entry, including notes, tags, triage state, and "changed since review" markers. Other local datasets are not touched.',
    label: 'Clear workspace',
  },
  environment: {
    title: 'Clear local environment?',
    description: 'This removes every local asset, inventory, component, correlation, and review record. Other local datasets are not touched.',
    label: 'Clear environment',
  },
  remediation: {
    title: 'Clear local remediation?',
    description: 'This removes every local plan, task, evidence record, and ledger event. Other local datasets are not touched.',
    label: 'Clear remediation',
  },
  history: {
    title: 'Clear local report history?',
    description: 'This removes the local history of generated reports (summary-only records). Other local datasets are not touched.',
    label: 'Clear report history',
  },
};

export function ClearConfirmDialog({ open, kind, exportFirst, busy, onCancel, onConfirm }: ClearConfirmDialogProps) {
  const copy = COPY[kind];
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', onKey);
    // Focus the cancel button by default — the safer
    // choice for a destructive action.
    if (confirmRef.current) confirmRef.current.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onCancel]);
  if (!open) return null;
  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="clear-confirm-title"
      aria-describedby="clear-confirm-description"
      className="fixed inset-0 z-50 flex items-center justify-center bg-radar-bg/70 p-4"
      data-testid={`clear-confirm-${kind}`}
    >
      <div className="panel max-w-md w-full p-4 text-[12px]" role="document">
        <header className="flex items-start justify-between gap-2">
          <h2 id="clear-confirm-title" className="flex items-center gap-1 text-sm font-semibold text-radar-text">
            <AlertTriangle className="h-4 w-4 text-radar-warn" /> {copy.title}
          </h2>
          <button type="button" onClick={onCancel} aria-label="Close confirmation" className="focus-ring rounded-md border border-radar-border p-1 text-radar-muted hover:text-radar-text">
            <X className="h-3.5 w-3.5" />
          </button>
        </header>
        <p id="clear-confirm-description" className="mt-2 text-radar-muted">
          {copy.description}
        </p>
        {exportFirst && (
          <p className="mt-2 flex items-start gap-1 rounded-md border border-radar-accent/30 bg-radar-accent/5 px-2 py-1 text-radar-text">
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-accent" />
            <span>
              Export-first recommended. The Export action on the local data card writes a verified JSON
              backup before any clear. Browser storage may not survive a tab close.
            </span>
          </p>
        )}
        <div className="mt-3 flex items-center justify-end gap-2 border-t border-radar-border/40 pt-3">
          <button
            ref={confirmRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            data-testid={`clear-confirm-${kind}-cancel`}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-3 py-1.5 text-xs text-radar-warn hover:bg-radar-warn/20 disabled:opacity-50"
            data-testid={`clear-confirm-${kind}-confirm`}
          >
            {busy ? 'Clearing…' : copy.label}
          </button>
        </div>
      </div>
    </div>
  );
}
