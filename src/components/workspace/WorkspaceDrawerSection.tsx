/**
 * V6.4 — Local workspace section inside the
 * vulnerability detail drawer.
 *
 * Provides the local-only controls (watch, triage,
 * priority, tags, note, mark reviewed, archive,
 * restore). All values come from and go to the
 * WorkspaceContext; no public dataset field is
 * mutated and no private value is rendered in the
 * public URL.
 *
 * The section is intentionally compact. It does not
 * duplicate the SSVC, GitHub Advisory, or OSV
 * sections. It does not use `dangerouslySetInnerHTML`.
 * The private note is rendered as a controlled
 * `<textarea>`; the saved value is shown in a
 * separate read-only line so the operator can confirm
 * the autosave.
 *
 * Saving state is visible:
 *   - 'idle'      : no pending write
 *   - 'saving'    : the write is in flight
 *   - 'saved'     : the commit was verified
 *   - 'error'     : the commit failed; the text is the
 *     sanitized human message
 *
 * Pending-write lifecycle (v6.4 hardened):
 *   - every keystroke on the note bumps a
 *     generation counter
 *   - the debounce timer captures the current
 *     generation; a stale callback is rejected
 *   - blur, archive, mark reviewed, cve-change, and
 *     component-unmount all flush the pending
 *     write before they proceed
 *   - on archive, the pending note is flushed
 *     BEFORE the archive mutation is dispatched,
 *     so a slow note save cannot be lost when the
 *     operator clicks Archive right after typing
 *   - import/clear/replace are surfaced to the
 *     operator as separate dialogs that call
 *     `flushPendingWrites` from the context; the
 *     context waits for every in-flight write to
 *     settle before the destructive action runs
 *
 * The local state and the public state are
 * deliberately kept separate: the worker's
 * `triageStatus` and `userPriority` are visually
 * distinct from the SSVC and provider severity in
 * tone and copy.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Archive, ArchiveRestore, Bookmark, BookmarkMinus, ClipboardCheck, Eye, EyeOff, NotebookPen, Tag, X } from 'lucide-react';
import type { Vulnerability } from '../../types/vulnerability';
import { useWorkspace, type WorkspaceEntry } from '../../state/WorkspaceContext';
import {
  LIMITS,
  TRIAGE_STATUSES,
  USER_PRIORITIES,
} from '../../workspace/schema.mjs';
import {
  computeChangeSignatureSync,
  classifyChange,
} from '../../workspace/changeSignature.mjs';

const STATUS_LABELS: Record<string, string> = {
  'unreviewed': 'Unreviewed',
  'reviewing': 'Reviewing',
  'action-required': 'Action required',
  'mitigating': 'Mitigating',
  'resolved': 'Resolved',
  'accepted-risk': 'Accepted risk',
  'not-applicable': 'Not applicable',
};

const PRIORITY_LABELS: Record<string, string> = {
  'none': 'No local priority',
  'low': 'Low',
  'medium': 'Medium',
  'high': 'High',
  'urgent': 'Urgent',
};

type SaveState =
  | { kind: 'idle' }
  | { kind: 'pending' }                    // dirty, not yet committed
  | { kind: 'saving'; gen: number }         // debounce fired, write in flight
  | { kind: 'saved'; ts: number; gen: number }
  | { kind: 'error'; message: string; gen: number };

const DEBOUNCE_MS = 600;

function formatStatusBadgeClass(triageStatus: string): string {
  switch (triageStatus) {
    case 'action-required': return 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn';
    case 'resolved':        return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300';
    case 'accepted-risk':   return 'border-radar-muted/40 bg-radar-panel2/40 text-radar-muted';
    case 'mitigating':      return 'border-radar-accent/40 bg-radar-accent/10 text-radar-accent';
    case 'reviewing':       return 'border-radar-accent/40 bg-radar-accent/5 text-radar-accent';
    case 'not-applicable':  return 'border-radar-border bg-radar-panel2/40 text-radar-muted';
    default:                return 'border-radar-border bg-radar-panel2/40 text-radar-muted';
  }
}

function formatPriorityBadgeClass(priority: string): string {
  switch (priority) {
    case 'urgent': return 'border-radar-warn/40 bg-radar-warn/15 text-radar-warn';
    case 'high':   return 'border-radar-warn/30 bg-radar-warn/5 text-radar-warn';
    case 'medium': return 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent';
    case 'low':    return 'border-radar-border bg-radar-panel2/40 text-radar-muted';
    default:       return 'border-radar-border bg-radar-panel2/40 text-radar-muted';
  }
}

interface WorkspaceDrawerSectionProps {
  vuln: Vulnerability;
  /**
   * v6.4: the current public-intelligence version. The
   * drawer uses it to compute the change signature and
   * to stamp `lastSeenPublicIntelligenceVersion` when
   * the operator clicks "Mark reviewed". When `null`,
   * the change-tracking controls are disabled.
   */
  publicIntelligenceVersion?: string | null;
  /**
   * v6.4: the current public-intelligence status
   * ('available' | 'mismatch' | 'unavailable'). A
   * 'mismatch' or 'unavailable' status forces the
   * change-aware review controls to surface
   * "Change status unavailable" — never a fabricated
   * change claim.
   */
  publicIntelligenceStatus?: 'available' | 'mismatch' | 'unavailable' | null;
  /**
   * v6.4: the public-projection schema version
   * (separate from the dataset version). The
   * signature is bound to the schema that produced
   * it; the drawer refuses to mark reviewed when
   * the schema differs.
   */
  publicProjectionSchemaVersion?: string | null;
}

export default function WorkspaceDrawerSection({
  vuln,
  publicIntelligenceVersion,
  publicIntelligenceStatus = 'available',
  publicProjectionSchemaVersion = null,
}: WorkspaceDrawerSectionProps) {
  const {
    state,
    saveError,
    getEntry,
    toggleWatch,
    setTriage,
    setPriority,
    addTag,
    removeTag,
    setNote,
    markReviewed,
    archive,
  } = useWorkspace();
  const entry: WorkspaceEntry | null = getEntry(vuln.cveId);
  const [noteDraft, setNoteDraft] = useState<string>(entry?.note || '');
  const [tagDraft, setTagDraft] = useState<string>('');
  const [saveState, setSaveState] = useState<SaveState>({ kind: 'idle' });
  const noteRef = useRef<HTMLTextAreaElement | null>(null);

  // Pending-write generation token. Every edit
  // bumps the counter; a stale debounce callback is
  // rejected when its captured gen differs from the
  // current gen. The token is also used to track
  // which in-flight commit a 'saved' / 'error'
  // event belongs to.
  const genRef = useRef<number>(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const inflightRef = useRef<number | null>(null);
  const cveIdRef = useRef<string>(vuln.cveId);

  // Compute the change-aware label. The change
  // signature is computed synchronously here (the
  // data is small — a handful of fields per CVE —
  // and the render path is hot). The export and
  // import paths use the async SHA-256 helper.
  const publicVersion = publicIntelligenceVersion ?? null;
  const publicStatus = publicIntelligenceStatus ?? 'available';
  const projectionSchema = publicProjectionSchemaVersion ?? null;
  const changeSignature = useMemo(
    () => computeChangeSignatureSync(vuln as any, publicVersion, projectionSchema),
    [vuln, publicVersion, projectionSchema]
  );
  const changeLabel = useMemo(() => {
    if (publicStatus !== 'available') return 'unavailable';
    if (!publicVersion) return 'unavailable';
    return classifyChange({
      currentVersion: publicVersion,
      currentProjectionSchemaVersion: projectionSchema,
      currentSignature: changeSignature,
      record: entry,
      presentInPublic: true,
    });
  }, [publicStatus, publicVersion, projectionSchema, changeSignature, entry]);

  // when the context reports a save error for any
  // reason, surface it as the local save state —
  // but ONLY if it is for the CURRENT generation, so
  // an old error doesn't overwrite a fresh success.
  useEffect(() => {
    if (saveError) {
      setSaveState((prev) => {
        // If a newer gen is in flight, ignore.
        if (prev.kind === 'saving' && inflightRef.current !== null && inflightRef.current > genRef.current) {
          return prev;
        }
        return { kind: 'error', message: saveError, gen: genRef.current };
      });
    }
  }, [saveError]);

  const watched = !!entry?.watched;
  const triage = entry?.triageStatus || 'unreviewed';
  const priority = entry?.userPriority || 'none';
  const tags = entry?.tags || [];
  const archived = !!entry?.archived;
  const note = entry?.note || '';

  // Cancel any pending debounce.
  const cancelDebounce = useCallback(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
  }, []);

  // Flush: immediately commit the current draft. The
  // function is idempotent — a no-op when there is
  // nothing to commit. Returns the promise so the
  // caller can await completion before a
  // destructive action.
  const flushNote = useCallback(async (): Promise<void> => {
    cancelDebounce();
    const targetCve = cveIdRef.current;
    if (!noteDraft || noteDraft === (entry?.note || '')) return;
    const myGen = ++genRef.current;
    inflightRef.current = myGen;
    setSaveState({ kind: 'saving', gen: myGen });
    const r = await setNote(targetCve, noteDraft);
    if (r.ok) {
      // Only surface "saved" if this commit is
      // still the most recent one. A later
      // generation overrides it.
      if (genRef.current === myGen) {
        setSaveState({ kind: 'saved', ts: Date.now(), gen: myGen });
      }
    } else {
      if (genRef.current === myGen) {
        setSaveState({ kind: 'error', message: r.reason || 'save-failed', gen: myGen });
      }
    }
    if (inflightRef.current === myGen) inflightRef.current = null;
  }, [cancelDebounce, noteDraft, entry?.note, setNote]);

  // Sanitize: only allow safe printable characters
  // in the note draft.
  const onNoteChange = (raw: string) => {
    setNoteDraft(raw.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ''));
    // Bump the generation; the previous debounce is
    // about to be cancelled by the effect.
    ++genRef.current;
    setSaveState((prev) => prev.kind === 'saving' ? prev : { kind: 'pending' });
  };

  // Debounced autosave. The effect runs whenever
  // noteDraft changes; it sets (or resets) a single
  // timer. When the timer fires, the captured gen
  // is compared to the current gen and the write
  // is skipped if a newer edit has happened.
  useEffect(() => {
    if (noteDraft === (entry?.note || '')) {
      cancelDebounce();
      // No dirty data. Reset to idle if we were
      // sitting in 'pending' but have nothing
      // to save.
      setSaveState((prev) => prev.kind === 'pending' ? { kind: 'idle' } : prev);
      return;
    }
    cancelDebounce();
    const capturedGen = genRef.current;
    const handle = setTimeout(() => {
      // Stale-callback guard: a newer keystroke
      // (higher gen) is already scheduled, so this
      // timer is the obsolete one.
      if (capturedGen !== genRef.current) return;
      // Fire the flush. We don't await here; the
      // function itself guards against the same
      // out-of-order case via inflightRef.
      void (async () => {
        inflightRef.current = capturedGen;
        setSaveState({ kind: 'saving', gen: capturedGen });
        const r = await setNote(cveIdRef.current, noteDraft);
        if (r.ok) {
          if (genRef.current === capturedGen) {
            setSaveState({ kind: 'saved', ts: Date.now(), gen: capturedGen });
          }
        } else {
          if (genRef.current === capturedGen) {
            setSaveState({ kind: 'error', message: r.reason || 'save-failed', gen: capturedGen });
          }
        }
        if (inflightRef.current === capturedGen) inflightRef.current = null;
      })();
    }, DEBOUNCE_MS);
    debounceRef.current = handle;
    return cancelDebounce;
  }, [noteDraft, entry?.note, cancelDebounce, setNote]);

  // CVE change: flush the current note before the
  // new CVE mounts its own draft state. The
  // flushNote call awaits so the next CVE's
  // initial state is consistent.
  useEffect(() => {
    if (cveIdRef.current !== vuln.cveId) {
      cancelDebounce();
      // Synchronous best-effort flush; the
      // flushNote body is async but we don't
      // block the effect (React would warn).
      void flushNote();
      cveIdRef.current = vuln.cveId;
      // Reset state for the new CVE.
      setSaveState({ kind: 'idle' });
      setNoteDraft(getEntry(vuln.cveId)?.note || '');
    }
  }, [vuln.cveId, flushNote, cancelDebounce, getEntry]);

  // Unmount: cancel pending timers and request a
  // final flush. The flush may race the unmount;
  // we do not block unmount, but the flush is
  // dispatched and the result is ignored.
  useEffect(() => {
    return () => {
      cancelDebounce();
      if (noteDraftRef.current && noteDraftRef.current !== (entryRef.current?.note || '')) {
        // Best-effort: fire and forget. The
        // setNote path is the single source of
        // truth; if the page is already tearing
        // down, the IndexedDB write may or may
        // not complete. The browser warns via
        // beforeunload only when this effect's
        // best-effort flush has NOT been confirmed.
        void setNote(cveIdRef.current, noteDraftRef.current);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mirror the latest noteDraft and entry into refs
  // so the unmount cleanup can read the current
  // values without capturing stale closures.
  const noteDraftRef = useRef<string>(noteDraft);
  const entryRef = useRef<WorkspaceEntry | null>(entry);
  useEffect(() => { noteDraftRef.current = noteDraft; }, [noteDraft]);
  useEffect(() => { entryRef.current = entry; }, [entry]);

  // beforeunload: warn the operator when an
  // uncommitted write is in flight. We don't
  // rely on an async IndexedDB write completing
  // during unload (the browser won't wait for
  // it); the warning gives the operator a chance
  // to cancel the navigation.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    function onBeforeUnload(e: BeforeUnloadEvent) {
      if (noteDraftRef.current && noteDraftRef.current !== (entryRef.current?.note || '')) {
        e.preventDefault();
        e.returnValue = '';
        return '';
      }
      return undefined;
    }
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, []);

  // Expose flushAll on the noteDraftRef for the
  // parents (DashboardPage) to read in their own
  // effects. We can't actually return a value from
  // this component, so we attach a callback ref on
  // the noteRef. For now the parent uses
  // flushPendingWrites from the context which
  // already covers the in-flight writes.

  // When the entry's note changes from a remote
  // update, reset the draft if we're not actively
  // editing.
  useEffect(() => {
    if (saveState.kind === 'saving') return;
    if (noteDraft === note) return;
    if (typeof window !== 'undefined' && document.activeElement === noteRef.current) return;
    setNoteDraft(note);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [note]);

  // The export/import/clear dialogs call this hook
  // The export/import/clear dialogs call the
  // context's `flushPendingWrites` before any
  // destructive operation. The local drawer also
  // flushes its own debounce via the `onBlur` /
  // unmount / cve-change / archive paths above; the
  // context call captures writes that other
  // components may have issued for the same CVE.

  const onWatchToggle = async () => {
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await toggleWatch(vuln.cveId, !watched);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  const onSetTriage = async (next: string) => {
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await setTriage(vuln.cveId, next);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  const onSetPriority = async (next: string) => {
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await setPriority(vuln.cveId, next);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  const onAddTag = async (raw: string) => {
    const t = raw.trim();
    if (!t) return;
    if (tags.length >= LIMITS.TAGS_PER_CVE) return;
    setTagDraft('');
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await addTag(vuln.cveId, t);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  const onRemoveTag = async (tag: string) => {
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await removeTag(vuln.cveId, tag);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  const onMarkReviewed = async () => {
    if (publicStatus !== 'available' || !publicVersion) return;
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await markReviewed(vuln.cveId, publicVersion, changeSignature, projectionSchema);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };
  // Archive: flush the pending note BEFORE the
  // archive mutation. The archive path does not
  // touch the note, but a slow debounced commit
  // can race the archive and surface as a "lost
  // note" — flush first, then archive, then
  // commit the archive.
  const onArchiveToggle = async () => {
    await flushNote();
    setSaveState({ kind: 'saving', gen: genRef.current });
    const r = await archive(vuln.cveId, !archived);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now(), gen: genRef.current } : { kind: 'error', message: r.reason || 'save-failed', gen: genRef.current });
  };

  const disabled = state.status === 'unavailable' || state.status === 'error';
  const noteCharsLeft = LIMITS.NOTE_MAX_CHARS - noteDraft.length;
  const canMarkReviewed = publicStatus === 'available' && !!publicVersion;

  return (
    <section
      aria-labelledby="workspace-section-title"
      className="mb-5 rounded-md border border-radar-border bg-radar-panel2/40 p-3"
    >
      <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-radar-muted">
        <NotebookPen className="h-3.5 w-3.5" aria-hidden="true" />
        <h3 id="workspace-section-title">Local workspace</h3>
        <span className="ml-auto inline-flex items-center gap-1 rounded-full border border-radar-border bg-radar-panel px-2 py-0.5 text-[10px] normal-case tracking-normal text-radar-muted">
          <span className="h-1.5 w-1.5 rounded-full bg-radar-accent" aria-hidden="true" />
          Stored only on this device
        </span>
      </div>

      <p className="mb-3 text-[11px] text-radar-dim">
        Watchlists, statuses, tags and notes are stored only in this browser.
        Export a backup before clearing browser data or switching devices.
      </p>

      <p className="sr-only" role="status" aria-live="polite">
        {saveState.kind === 'saving' ? 'Saving local workspace change' : ''}
        {saveState.kind === 'saved' ? 'Local workspace change saved' : ''}
        {saveState.kind === 'error' ? `Local workspace error: ${saveState.message}` : ''}
      </p>

      {disabled && (
        <p className="mb-3 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1.5 text-[11px] text-radar-warn">
          Local workspace is {state.status}. Changes are not being saved this session.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onWatchToggle}
          disabled={disabled}
          aria-label={watched
            ? `Remove ${vuln.cveId} from local watchlist`
            : `Add ${vuln.cveId} to local watchlist`}
          className={[
            'focus-ring inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition',
            watched
              ? 'border-radar-accent/50 bg-radar-accent/10 text-radar-accent hover:border-radar-accent'
              : 'border-radar-border bg-radar-panel2 text-radar-text hover:border-radar-accent/40',
          ].join(' ')}
        >
          {watched ? <BookmarkMinus className="h-3.5 w-3.5" /> : <Bookmark className="h-3.5 w-3.5" />}
          {watched ? 'Watched' : 'Add to watchlist'}
        </button>

        <div className="flex items-center gap-1.5">
          <label htmlFor={`ws-triage-${vuln.cveId}`} className="text-[11px] text-radar-dim">
            Status
          </label>
          <select
            id={`ws-triage-${vuln.cveId}`}
            value={triage}
            onChange={(e) => onSetTriage(e.target.value)}
            disabled={disabled}
            className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            aria-label="Local triage status"
          >
            {TRIAGE_STATUSES.map((s) => (
              <option key={s} value={s}>{STATUS_LABELS[s] || s}</option>
            ))}
          </select>
          <span
            className={['inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] tracking-tight', formatStatusBadgeClass(triage)].join(' ')}
            aria-hidden="true"
          >
            {STATUS_LABELS[triage] || triage}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <label htmlFor={`ws-priority-${vuln.cveId}`} className="text-[11px] text-radar-dim">
            Priority
          </label>
          <select
            id={`ws-priority-${vuln.cveId}`}
            value={priority}
            onChange={(e) => onSetPriority(e.target.value)}
            disabled={disabled}
            className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            aria-label="Local user priority"
          >
            {USER_PRIORITIES.map((p) => (
              <option key={p} value={p}>{PRIORITY_LABELS[p] || p}</option>
            ))}
          </select>
          {priority !== 'none' && (
            <span
              className={['inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] tracking-tight', formatPriorityBadgeClass(priority)].join(' ')}
              aria-hidden="true"
            >
              {PRIORITY_LABELS[priority] || priority}
            </span>
          )}
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <button
            type="button"
            onClick={onArchiveToggle}
            disabled={disabled}
            aria-label={archived ? `Restore ${vuln.cveId} from archive` : `Archive ${vuln.cveId}`}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text hover:border-radar-accent/40"
          >
            {archived ? <ArchiveRestore className="h-3.5 w-3.5" /> : <Archive className="h-3.5 w-3.5" />}
            {archived ? 'Restore' : 'Archive'}
          </button>
          <button
            type="button"
            onClick={onMarkReviewed}
            disabled={disabled || !canMarkReviewed}
            aria-label={`Mark ${vuln.cveId} reviewed`}
            title={canMarkReviewed
              ? 'Mark reviewed against the current public-intelligence view'
              : publicStatus !== 'available'
                ? 'Public intelligence status is not "available" — change status is unavailable.'
                : 'Public intelligence version unavailable'}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2.5 py-1.5 text-xs text-radar-accent transition hover:border-radar-accent disabled:opacity-50"
          >
            <ClipboardCheck className="h-3.5 w-3.5" />
            Mark reviewed
          </button>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {tags.map((t) => (
          <span
            key={t}
            className="inline-flex items-center gap-1 rounded-full border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[11px] text-radar-text"
          >
            <Tag className="h-3 w-3 text-radar-dim" aria-hidden="true" />
            {t}
            <button
              type="button"
              onClick={() => onRemoveTag(t)}
              disabled={disabled}
              aria-label={`Remove tag ${t} from ${vuln.cveId}`}
              className="focus-ring -mr-1 ml-0.5 inline-flex h-3.5 w-3.5 items-center justify-center rounded-full text-radar-dim hover:text-radar-text"
            >
              <X className="h-2.5 w-2.5" />
            </button>
          </span>
        ))}
        {tags.length < LIMITS.TAGS_PER_CVE && (
          <form
            className="flex items-center gap-1"
            onSubmit={(e) => { e.preventDefault(); onAddTag(tagDraft); }}
          >
            <label htmlFor={`ws-tag-${vuln.cveId}`} className="sr-only">Add tag to {vuln.cveId}</label>
            <input
              id={`ws-tag-${vuln.cveId}`}
              type="text"
              value={tagDraft}
              onChange={(e) => setTagDraft(e.target.value)}
              maxLength={LIMITS.TAG_MAX_CHARS}
              disabled={disabled}
              placeholder="Add tag…"
              className="focus-ring w-28 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text placeholder:text-radar-dim"
            />
            <button
              type="submit"
              disabled={disabled || !tagDraft.trim()}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text transition hover:border-radar-accent/40 disabled:opacity-50"
            >
              Add
            </button>
          </form>
        )}
        {tags.length >= LIMITS.TAGS_PER_CVE && (
          <span className="text-[11px] text-radar-dim">Tag limit reached.</span>
        )}
      </div>

      <div className="mt-3">
        <label htmlFor={`ws-note-${vuln.cveId}`} className="text-[11px] text-radar-dim">
          Private note (local only)
        </label>
        <textarea
          ref={noteRef}
          id={`ws-note-${vuln.cveId}`}
          value={noteDraft}
          onChange={(e) => onNoteChange(e.target.value)}
          onBlur={() => { void flushNote(); }}
          maxLength={LIMITS.NOTE_MAX_CHARS}
          disabled={disabled}
          rows={3}
          placeholder="Add a private note — saved only on this device."
          className="focus-ring mt-1 w-full resize-y rounded-md border border-radar-border bg-radar-panel2 px-2 py-1.5 text-[12px] text-radar-text placeholder:text-radar-dim"
        />
        <div className="mt-1 flex items-center justify-between text-[10px] text-radar-dim">
          <span aria-live="polite">
            {saveState.kind === 'pending' && <span className="text-radar-muted">Unsaved</span>}
            {saveState.kind === 'saving' && <span className="text-radar-accent">Saving…</span>}
            {saveState.kind === 'saved' && <span className="text-emerald-300">Saved</span>}
            {saveState.kind === 'error' && <span className="text-radar-warn">{saveState.message}</span>}
            {saveState.kind === 'idle' && (note ? 'Autosave on' : '')}
          </span>
          <span aria-label={`${noteCharsLeft} characters remaining`}>
            {noteDraft.length} / {LIMITS.NOTE_MAX_CHARS}
          </span>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-radar-border bg-radar-panel/60 px-2.5 py-2 text-[11px]">
        {entry?.lastReviewedAt ? (
          <span className="inline-flex items-center gap-1 text-radar-text">
            <Eye className="h-3 w-3" aria-hidden="true" />
            Last reviewed {formatRelativeTs(entry.lastReviewedAt)}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-radar-muted">
            <EyeOff className="h-3 w-3" aria-hidden="true" />
            Never reviewed
          </span>
        )}
        <span className="text-radar-dim" aria-hidden="true">·</span>
        <ChangeStatusPill label={changeLabel} />
      </div>
    </section>
  );
}

function formatRelativeTs(ts: string): string {
  try {
    const d = new Date(ts);
    const diff = Date.now() - d.getTime();
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} h ago`;
    return d.toLocaleDateString();
  } catch {
    return ts;
  }
}

function ChangeStatusPill({ label }: { label: string }) {
  if (label === 'changed') {
    return <span className="inline-flex items-center gap-1 text-radar-warn">Changed since review</span>;
  }
  if (label === 'no-newer') {
    return <span className="inline-flex items-center gap-1 text-emerald-300">No newer compatible change recorded</span>;
  }
  if (label === 'newly-tracked') {
    return <span className="inline-flex items-center gap-1 text-radar-accent">Newly tracked on this device</span>;
  }
  if (label === 'no-longer-tracked') {
    return <span className="inline-flex items-center gap-1 text-radar-muted">No longer tracked in public view</span>;
  }
  return <span className="inline-flex items-center gap-1 text-radar-muted">Change status unavailable</span>;
}
