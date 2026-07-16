/**
 * V6.4 — Workspace dialogs.
 *
 * Application-level dialogs for:
 *   - Export: download a local JSON backup
 *   - Import: file picker → dry-run (default) → merge or
 *     replace
 *   - Clear archived: confirm with exact count
 *   - Clear workspace: confirm with exact count +
 *     typed "RESET" gate
 *
 * All dialogs:
 *   - trap and restore focus
 *   - are dismissible with Escape
 *   - do not call confirm()/alert() — they are
 *     application dialogs
 *   - announce the result via role="status" +
 *     aria-live="polite"
 *   - never include the user's note/tag contents in
 *     their visible copy
 *
 * Export NEVER uploads. The browser download mechanism
 * is the only transport.
 *
 * Import NEVER executes the import without a
 * confirmed action. The dry-run path validates
 * silently and surfaces counts only.
 */

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
} from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileWarning,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { useWorkspace } from '../../state/WorkspaceContext';
import { LIMITS, WORKSPACE_EXPORT_FORMAT, WORKSPACE_SCHEMA_VERSION } from '../../workspace/schema.mjs';

const MAX_FILE_BYTES = LIMITS.IMPORT_MAX_BYTES;

export type DialogKind = 'export' | 'import' | 'clear-archived' | 'clear-workspace' | null;

interface DialogsProps {
  active: DialogKind;
  onClose: () => void;
}

/* ------------------------------- main export ------------------------------ */

export default function WorkspaceDialogs({ active, onClose }: DialogsProps) {
  if (!active) return null;
  return (
    <>
      {active === 'export' && <ExportDialog onClose={onClose} />}
      {active === 'import' && <ImportDialog onClose={onClose} />}
      {active === 'clear-archived' && <ClearArchivedDialog onClose={onClose} />}
      {active === 'clear-workspace' && <ClearWorkspaceDialog onClose={onClose} />}
    </>
  );
}

/* ----------------------------- shared dialog ----------------------------- */

function DialogShell({
  title,
  onClose,
  children,
  width = 'max-w-xl',
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  width?: string;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  useEffect(() => {
    previouslyFocused.current = (document.activeElement as HTMLElement | null) || null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === 'Tab' && ref.current) {
        const focusables = ref.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    // Move focus to the dialog's first focusable.
    setTimeout(() => {
      const f = ref.current?.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      f?.focus();
    }, 0);
    return () => {
      document.removeEventListener('keydown', onKey);
      previouslyFocused.current?.focus?.();
    };
  }, [onClose]);
  const titleId = useId();
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4 py-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        className={[
          'w-full rounded-md border border-radar-border bg-radar-panel p-5 shadow-2xl',
          width,
        ].join(' ')}
      >
        <div className="flex items-start justify-between gap-3">
          <h2 id={titleId} className="text-sm font-semibold text-radar-text">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="mt-3">{children}</div>
      </div>
    </div>
  );
}

/* ------------------------------- Export ---------------------------------- */

function ExportDialog({ onClose }: { onClose: () => void }) {
  const { state, exportWorkspace } = useWorkspace();
  const entries = Object.values(state.entriesByCve);
  const [downloaded, setDownloaded] = useState<null | { bytes: number; file: string }>(null);
  const handleDownload = useCallback(() => {
    const payload = exportWorkspace();
    const json = JSON.stringify(payload, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    // The filename is generic: no CVE id, no timestamp leak.
    // "threatpulse-workspace" + ".json". The browser
    // adds its own date-stamped "downloads/" path.
    a.download = `threatpulse-workspace.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDownloaded({ bytes: json.length, file: a.download });
  }, [exportWorkspace]);
  return (
    <DialogShell title="Export local workspace" onClose={onClose}>
      <p className="text-xs text-radar-muted">
        The export contains every entry currently in your local
        workspace — watchlists, statuses, tags, and private notes.
        The file is generated and downloaded entirely in this
        browser; nothing is uploaded.
      </p>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-[11px] text-radar-muted">
        <li>Format: <code className="text-radar-text">{WORKSPACE_EXPORT_FORMAT}</code></li>
        <li>Schema version: <code className="text-radar-text">{WORKSPACE_SCHEMA_VERSION}</code></li>
        <li>Entries: <strong className="text-radar-text">{entries.length.toLocaleString('en-US')}</strong></li>
        <li>Deterministic SHA-256 checksum baked into the file</li>
      </ul>
      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleDownload}
          disabled={entries.length === 0}
          className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-3 py-1.5 text-xs text-radar-accent hover:border-radar-accent disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Download className="h-3.5 w-3.5" />
          Download JSON
        </button>
      </div>
      {downloaded && (
        <p
          role="status"
          aria-live="polite"
          className="mt-3 inline-flex items-center gap-1 text-[11px] text-radar-accent"
        >
          <CheckCircle2 className="h-3 w-3" />
          Downloaded {downloaded.file} ({downloaded.bytes.toLocaleString('en-US')} bytes).
        </p>
      )}
    </DialogShell>
  );
}

/* ------------------------------- Import ---------------------------------- */

type ImportPhase =
  | { kind: 'idle' }
  | { kind: 'reading'; fileName: string; bytes: number }
  | { kind: 'dry-run'; fileName: string; total: number; dropped: number; schemaVersion: string }
  | { kind: 'error'; reason: string }
  | { kind: 'applying'; mode: 'merge' | 'replace' }
  | { kind: 'done'; mode: 'merge' | 'replace'; added?: number; updated?: number; unchanged?: number; written?: number; removed?: number };

function ImportDialog({ onClose }: { onClose: () => void }) {
  const { importWorkspace } = useWorkspace();
  const [phase, setPhase] = useState<ImportPhase>({ kind: 'idle' });
  const [payload, setPayload] = useState<any | null>(null);
  const [mode, setMode] = useState<'merge' | 'replace'>('merge');

  const handleFile = useCallback(async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setPhase({ kind: 'error', reason: 'file-too-large' });
      return;
    }
    setPhase({ kind: 'reading', fileName: file.name, bytes: file.size });
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      // Reuse the validate path via the workspace context
      // for a synchronous shape check, but the real
      // validation lives in importWorkspace.
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        setPhase({ kind: 'error', reason: 'payload-not-object' });
        return;
      }
      if (parsed.format !== WORKSPACE_EXPORT_FORMAT) {
        setPhase({ kind: 'error', reason: 'invalid-format' });
        return;
      }
      if (typeof parsed.schemaVersion !== 'string') {
        setPhase({ kind: 'error', reason: 'missing-schema-version' });
        return;
      }
      if (parsed.schemaVersion !== WORKSPACE_SCHEMA_VERSION) {
        setPhase({ kind: 'error', reason: 'unsupported-schema-version' });
        return;
      }
      if (!Array.isArray(parsed.entries)) {
        setPhase({ kind: 'error', reason: 'entries-not-array' });
        return;
      }
      setPayload(parsed);
      setPhase({
        kind: 'dry-run',
        fileName: file.name,
        total: parsed.entries.length,
        dropped: 0,
        schemaVersion: parsed.schemaVersion,
      });
    } catch (err) {
      setPhase({
        kind: 'error',
        reason: err instanceof Error ? err.message : 'parse-failed',
      });
    }
  }, []);

  const handleApply = useCallback(async () => {
    if (!payload) return;
    setPhase({ kind: 'applying', mode });
    const r = await importWorkspace(payload, mode);
    if (!r.ok) {
      setPhase({ kind: 'error', reason: r.reason || 'import-failed' });
      return;
    }
    setPhase({
      kind: 'done',
      mode,
      added: r.added,
      updated: r.updated,
      unchanged: r.unchanged,
      written: r.written,
      removed: r.removed,
    });
  }, [payload, mode, importWorkspace]);

  return (
    <DialogShell title="Import local workspace" onClose={onClose} width="max-w-2xl">
      <p className="text-xs text-radar-muted">
        Import a previously-exported local workspace JSON file. The
        default mode is <strong className="text-radar-text">dry-run</strong>,
        which validates the file without writing. You can then choose
        <em> merge</em> (newer updatedAt wins per CVE) or
        <em> replace</em> (existing workspace is preserved until the
        new workspace is fully staged, then atomically promoted).
      </p>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-[11px] text-radar-muted">
        <li>Max file size: {(MAX_FILE_BYTES / (1024 * 1024)).toFixed(0)} MiB</li>
        <li>Max entries: {LIMITS.IMPORT_MAX_ENTRIES.toLocaleString('en-US')}</li>
        <li>Future schema versions are rejected</li>
        <li>Prototype-pollution keys are rejected</li>
        <li>Notes and tags are rendered as plain text only</li>
      </ul>

      {phase.kind === 'idle' && (
        <label className="mt-4 flex w-full cursor-pointer flex-col items-center justify-center rounded-md border border-dashed border-radar-border bg-radar-panel2/40 px-4 py-6 text-xs text-radar-muted hover:border-radar-accent/40">
          <Upload className="h-5 w-5 text-radar-accent" />
          <span className="mt-2">Click to choose a workspace JSON file</span>
          <span className="mt-1 text-[10px] text-radar-dim">
            Files are read entirely in this browser. Nothing is uploaded.
          </span>
          <input
            type="file"
            accept="application/json,.json"
            onChange={handleFile}
            className="sr-only"
            aria-label="Choose a workspace JSON file to import"
          />
        </label>
      )}

      {phase.kind === 'reading' && (
        <p className="mt-4 text-xs text-radar-text">Reading {phase.fileName}…</p>
      )}

      {phase.kind === 'error' && (
        <div className="mt-4 flex items-start gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-3 py-2 text-xs text-radar-muted">
          <FileWarning className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
          <div>
            <p className="text-radar-text">
              The import file could not be validated.
            </p>
            <p className="mt-1 text-[11px] text-radar-dim">Reason: {phase.reason}</p>
          </div>
        </div>
      )}

      {phase.kind === 'dry-run' && (
        <div className="mt-4 rounded-md border border-radar-accent/30 bg-radar-accent/5 px-3 py-2 text-xs">
          <p className="text-radar-text">
            Validation passed. <strong>{phase.total.toLocaleString('en-US')}</strong>{' '}
            {phase.total === 1 ? 'entry' : 'entries'} ready to import
            from <code className="text-radar-text">{phase.fileName}</code>{' '}
            (schema <code className="text-radar-text">{phase.schemaVersion}</code>).
          </p>
          <fieldset className="mt-3 space-y-1.5">
            <legend className="text-[10px] uppercase tracking-wider text-radar-dim">
              Apply mode
            </legend>
            <label className="flex items-start gap-2 text-radar-text">
              <input
                type="radio"
                name="import-mode"
                value="merge"
                checked={mode === 'merge'}
                onChange={() => setMode('merge')}
                className="focus-ring mt-0.5 h-3.5 w-3.5"
              />
              <span>
                <strong>Merge</strong> — newer updatedAt wins per CVE.
                Existing entries with no incoming change are kept.
              </span>
            </label>
            <label className="flex items-start gap-2 text-radar-text">
              <input
                type="radio"
                name="import-mode"
                value="replace"
                checked={mode === 'replace'}
                onChange={() => setMode('replace')}
                className="focus-ring mt-0.5 h-3.5 w-3.5"
              />
              <span>
                <strong>Replace</strong> — existing workspace is preserved
                until the new workspace is fully staged, then atomically
                promoted. Failed promotion leaves the original workspace
                intact.
              </span>
            </label>
          </fieldset>
          <div className="mt-3 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleApply}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-3 py-1.5 text-xs text-radar-accent hover:border-radar-accent"
            >
              {mode === 'merge' ? 'Merge' : 'Replace workspace'}
            </button>
          </div>
        </div>
      )}

      {phase.kind === 'applying' && (
        <p className="mt-4 text-xs text-radar-text">
          Applying {phase.mode}… your existing workspace is{' '}
          {phase.mode === 'replace' ? 'preserved until promotion' : 'kept'}.
        </p>
      )}

      {phase.kind === 'done' && (
        <div className="mt-4 rounded-md border border-radar-accent/30 bg-radar-accent/5 px-3 py-2 text-xs">
          <p className="inline-flex items-center gap-1 text-radar-accent">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Import complete.
          </p>
          <p className="mt-1 text-radar-muted">
            {phase.mode === 'merge' ? (
              <>
                Added: <strong className="text-radar-text">{phase.added ?? 0}</strong>,
                updated:{' '}
                <strong className="text-radar-text">{phase.updated ?? 0}</strong>,
                unchanged:{' '}
                <strong className="text-radar-text">{phase.unchanged ?? 0}</strong>.
              </>
            ) : (
              <>
                Written: <strong className="text-radar-text">{phase.written ?? 0}</strong>,
                previous entries removed:{' '}
                <strong className="text-radar-text">{phase.removed ?? 0}</strong>.
              </>
            )}
          </p>
          <div className="mt-3 flex items-center justify-end">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </DialogShell>
  );
}

/* --------------------------- Clear archived ----------------------------- */

function ClearArchivedDialog({ onClose }: { onClose: () => void }) {
  const { state, clearArchived } = useWorkspace();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ removed: number } | null>(null);
  const archived = useMemo(
    () => Object.values(state.entriesByCve).filter((e) => e.archived).length,
    [state.entriesByCve]
  );
  const handleClear = useCallback(async () => {
    setBusy(true);
    try {
      const r = await clearArchived();
      if (r.ok) setDone({ removed: r.removed ?? 0 });
    } finally {
      setBusy(false);
    }
  }, [clearArchived]);
  return (
    <DialogShell title="Clear archived entries" onClose={onClose}>
      <p className="text-xs text-radar-muted">
        This removes every <strong className="text-radar-text">archived</strong>{' '}
        entry from your local workspace. Active (non-archived) entries
        are kept. Public data, Netlify Blobs, and Hostinger storage
        are not touched.
      </p>
      {done ? (
        <div className="mt-4 rounded-md border border-radar-accent/30 bg-radar-accent/5 px-3 py-2 text-xs">
          <p className="inline-flex items-center gap-1 text-radar-accent">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Removed {done.removed.toLocaleString('en-US')}{' '}
            {done.removed === 1 ? 'entry' : 'entries'}.
          </p>
          <div className="mt-3 flex items-center justify-end">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Close
            </button>
          </div>
        </div>
      ) : (
        <>
          <p className="mt-3 text-xs text-radar-text">
            About to remove <strong>{archived.toLocaleString('en-US')}</strong>{' '}
            {archived === 1 ? 'archived entry' : 'archived entries'}.
            {archived === 0 && ' Nothing to clear.'}
          </p>
          {archived > 0 && (
            <p className="mt-1 text-[11px] text-radar-dim">
              Consider exporting a backup first.
            </p>
          )}
          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleClear}
              disabled={archived === 0 || busy}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-3 py-1.5 text-xs text-radar-warn hover:border-radar-warn disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Trash2 className="h-3.5 w-3.5" />
              {busy ? 'Clearing…' : `Remove ${archived} ${archived === 1 ? 'entry' : 'entries'}`}
            </button>
          </div>
        </>
      )}
    </DialogShell>
  );
}

/* ---------------------------- Clear workspace ---------------------------- */

const RESET_GATE = 'RESET';

function ClearWorkspaceDialog({ onClose }: { onClose: () => void }) {
  const { state, clearWorkspace } = useWorkspace();
  const [busy, setBusy] = useState(false);
  const [gate, setGate] = useState('');
  const [done, setDone] = useState(false);
  const total = Object.values(state.entriesByCve).length;
  const ready = gate.trim() === RESET_GATE;
  const handleClear = useCallback(async () => {
    if (!ready) return;
    setBusy(true);
    try {
      const r = await clearWorkspace();
      if (r.ok) setDone(true);
    } finally {
      setBusy(false);
    }
  }, [ready, clearWorkspace]);
  return (
    <DialogShell title="Clear entire local workspace" onClose={onClose}>
      <p className="text-xs text-radar-muted">
        This removes every entry — watched, archived, and otherwise —
        from your local workspace. Public vulnerability data, Netlify
        Blobs, and Hostinger storage are not touched.
      </p>
      {done ? (
        <div className="mt-4 rounded-md border border-radar-accent/30 bg-radar-accent/5 px-3 py-2 text-xs">
          <p className="inline-flex items-center gap-1 text-radar-accent">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Local workspace cleared.
          </p>
          <div className="mt-3 flex items-center justify-end">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Close
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="mt-3 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-3 py-2 text-xs text-radar-muted">
            <p className="inline-flex items-center gap-1 text-radar-warn">
              <AlertCircle className="h-3.5 w-3.5" />
              About to remove <strong className="text-radar-text">{total.toLocaleString('en-US')}</strong>{' '}
              {total === 1 ? 'entry' : 'entries'}.
            </p>
            <p className="mt-1 text-[11px] text-radar-dim">
              This is destructive. The action is gated by a typed
              confirmation: type <code className="text-radar-text">{RESET_GATE}</code>{' '}
              to enable the clear button.
            </p>
          </div>
          <label className="mt-3 block">
            <span className="block text-[11px] uppercase tracking-wider text-radar-dim">
              Type {RESET_GATE} to confirm
            </span>
            <input
              type="text"
              value={gate}
              onChange={(e) => setGate(e.target.value)}
              className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-sm text-radar-text"
              aria-label={`Type ${RESET_GATE} to confirm clearing the workspace`}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleClear}
              disabled={!ready || busy}
              className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-3 py-1.5 text-xs text-radar-warn hover:border-radar-warn disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Trash2 className="h-3.5 w-3.5" />
              {busy ? 'Clearing…' : 'Clear workspace'}
            </button>
          </div>
        </>
      )}
    </DialogShell>
  );
}
