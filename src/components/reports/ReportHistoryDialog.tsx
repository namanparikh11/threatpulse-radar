/**
 * V6.5 — Report history dialog.
 *
 * Renders the local report-history list, lets the
 * operator delete a single entry, clear all entries,
 * and disable the history. The dialog is purely
 * informational: it never re-fetches the network,
 * never writes to the URL, and never logs to the
 * console. The full report body is NEVER stored
 * here (history is summary-only).
 *
 * The "Clear history" action has its own clearing
 * warning, separate from the workspace clearing
 * warning, so the operator cannot confuse the two.
 */

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, History as HistoryIcon, Trash2 } from 'lucide-react';
import {
  addHistoryEntry,
  clearHistory,
  historyAvailable,
  isHistoryEnabled,
  listHistoryEntries,
  removeHistoryEntry,
  setHistoryEnabled,
  type HistoryEntry,
} from '../../reports/history.mjs';
import ReportDialogShell from './ReportDialogShell';

export interface ReportHistoryDialogProps {
  onClose: () => void;
}

function fmtDate(s: string): string {
  if (typeof s !== 'string' || s.length === 0) return '—';
  return s.replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

export default function ReportHistoryDialog({ onClose }: ReportHistoryDialogProps) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [enabled, setEnabled] = useState<boolean>(true);
  const [busy, setBusy] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState<boolean>(false);

  const refresh = useCallback(async () => {
    if (!historyAvailable()) {
      setEntries([]);
      setError('History is unavailable: IndexedDB is not exposed in this browser session.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const list = await listHistoryEntries();
      setEntries(list);
    } catch {
      setError('Could not read the history.');
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    setEnabled(isHistoryEnabled());
    void refresh();
  }, [refresh]);

  const handleDelete = useCallback(async (reportId: string) => {
    setBusy(true);
    setError(null);
    try {
      const out = await removeHistoryEntry(reportId);
      if (!out.ok) setError(`Could not remove entry: ${out.reason || 'unknown-error'}`);
      await refresh();
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  const handleClear = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const out = await clearHistory();
      if (!out.ok) setError(`Could not clear history: ${out.reason || 'unknown-error'}`);
      setShowClearConfirm(false);
      await refresh();
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  const handleToggleEnabled = useCallback(() => {
    const next = !enabled;
    setHistoryEnabled(next);
    setEnabled(next);
    if (next) {
      // Re-enable: don't auto-add, but allow future exports.
    } else {
      // Disable: keep existing entries on disk; they will be
      // hidden when listHistoryEntries is called and addHistoryEntry
      // becomes a no-op.
    }
  }, [enabled]);

  return (
    <ReportDialogShell title="Report history" onClose={onClose}>
      <p className="text-[11px] text-radar-muted" data-testid="report-history-preamble">
        Local report history records one entry per export. Full reports, private notes, and tags are never stored.
      </p>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-radar-border bg-radar-panel2/30 px-3 py-2">
        <label className="inline-flex items-center gap-2 text-[12px] text-radar-text">
          <input
            type="checkbox"
            checked={enabled}
            onChange={handleToggleEnabled}
            className="focus-ring h-3.5 w-3.5"
            data-testid="report-history-enabled"
            aria-label="Enable report history"
          />
          <span>Enable local report history</span>
        </label>
        <span className="text-[10px] text-radar-dim">
          {entries.length} / 100 entries
        </span>
      </div>

      {error && (
        <p role="alert" aria-live="polite" className="mt-3 inline-flex items-center gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="report-history-error">
          <AlertTriangle className="h-3 w-3" />
          {error}
        </p>
      )}

      <div className="mt-3 max-h-[50vh] overflow-x-auto overflow-y-auto rounded-md border border-radar-border bg-radar-panel2/40">
        {busy && entries.length === 0 ? (
          <p className="px-3 py-3 text-center text-[11px] text-radar-dim">Loading…</p>
        ) : entries.length === 0 ? (
          <p className="px-3 py-3 text-center text-[11px] text-radar-dim">
            No history entries yet. Build and export a report to add one.
          </p>
        ) : (
          <table className="w-full min-w-[560px] border-collapse text-[11px]">
            <caption className="sr-only">Local report history entries</caption>
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-radar-muted">
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Generated</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Type</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">CVEs</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Public intel</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Notes</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">SHA-256</th>
                <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Action</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.reportId} className="align-top">
                  <td className="border-b border-radar-border/40 px-2 py-1 font-mono text-radar-text">{fmtDate(e.generatedAt)}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{e.reportType || '—'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{e.cveCount}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{e.publicIntelligenceStatus || 'unavailable'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{e.includePrivateNotes ? 'included' : 'excluded'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 break-all font-mono text-radar-muted">
                    {e.checksum ? e.checksum.slice(0, 12) : '—'}
                  </td>
                  <td className="border-b border-radar-border/40 px-2 py-1">
                    <button
                      type="button"
                      onClick={() => handleDelete(e.reportId)}
                      className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn"
                      aria-label={`Delete history entry for ${e.reportId}`}
                      data-testid="report-history-delete"
                    >
                      <Trash2 className="h-3 w-3" />
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-[10px] text-radar-dim">
          <HistoryIcon className="mr-1 inline h-3 w-3" />
          Stored only in this browser via IndexedDB. Disable to stop future entries; existing entries are kept.
        </p>
        <div className="flex items-center gap-2">
          {showClearConfirm ? (
            <>
              <span className="text-[11px] text-radar-warn" data-testid="report-history-clear-warning">
                This removes all report history entries. This is separate from clearing the workspace.
              </span>
              <button
                type="button"
                onClick={handleClear}
                className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-2 py-1 text-[11px] text-radar-warn"
                data-testid="report-history-clear-confirm"
              >
                Confirm clear
              </button>
              <button
                type="button"
                onClick={() => setShowClearConfirm(false)}
                className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted"
              >
                Cancel
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={() => setShowClearConfirm(true)}
              disabled={entries.length === 0}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn disabled:opacity-50 disabled:cursor-not-allowed"
              data-testid="report-history-clear"
            >
              <Trash2 className="h-3 w-3" />
              Clear history
            </button>
          )}
        </div>
      </div>
    </ReportDialogShell>
  );
}

// Export the addHistoryEntry so other components
// (the ReportBuilder + ReportDialogShell host) can
// append a new entry after a successful export.
export { addHistoryEntry };
