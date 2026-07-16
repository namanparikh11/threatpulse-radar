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
 * The local state and the public state are
 * deliberately kept separate: the worker's
 * `triageStatus` and `userPriority` are visually
 * distinct from the SSVC and provider severity in
 * tone and copy.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Archive, ArchiveRestore, Bookmark, BookmarkMinus, ClipboardCheck, Eye, EyeOff, NotebookPen, Tag, X } from 'lucide-react';
import type { Vulnerability } from '../../types/vulnerability';
import { useWorkspace, type WorkspaceEntry } from '../../state/WorkspaceContext';
import {
  LIMITS,
  TRIAGE_STATUSES,
  USER_PRIORITIES,
} from '../../workspace/schema.mjs';
import {
  computeChangeSignature,
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
  | { kind: 'saving' }
  | { kind: 'saved'; ts: number }
  | { kind: 'error'; message: string };

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

export default function WorkspaceDrawerSection({ vuln }: { vuln: Vulnerability }) {
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

  // Keep the draft in sync when the entry changes
  // externally (e.g. another tab wrote a newer
  // record). The autosave only fires when the
  // operator types; an external write is mirrored on
  // the next render.
  useEffect(() => {
    if (saveState.kind === 'saving' || saveState.kind === 'saved') return;
    setNoteDraft(entry?.note || '');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry?.cveId, entry?.note]);

  // Compute the change-aware labels from the V6.1
  // public-intelligence fields. The workspace never
  // stores the public dataset; the signature is
  // computed in-memory from the vulnerability prop.
  const publicVersion = (vuln as any).publicIntelligenceVersion ?? null;
  const changeSignature = useMemo(() => computeChangeSignature(vuln as any, publicVersion), [vuln, publicVersion]);
  const changeLabel = useMemo(() => classifyChange({
    currentVersion: publicVersion,
    currentSignature: changeSignature,
    record: entry,
    presentInPublic: true,
  }), [publicVersion, changeSignature, entry]);

  // When the context reports a save error for any
  // reason, surface it as the local save state.
  useEffect(() => {
    if (saveError) {
      setSaveState({ kind: 'error', message: saveError });
    }
  }, [saveError]);

  const watched = !!entry?.watched;
  const triage = entry?.triageStatus || 'unreviewed';
  const priority = entry?.userPriority || 'none';
  const tags = entry?.tags || [];
  const archived = !!entry?.archived;
  const note = entry?.note || '';

  // Sanitize: only allow safe printable characters
  // in the note draft. The schema layer also strips
  // control characters; the UI just refuses them at
  // the keystroke level for a smoother experience.
  const onNoteChange = (raw: string) => {
    setNoteDraft(raw.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ''));
    if (saveState.kind === 'saved' || saveState.kind === 'idle') {
      setSaveState({ kind: 'idle' });
    }
  };

  // Debounced autosave. The draft is committed
  // 600 ms after the operator stops typing.
  useEffect(() => {
    if (noteDraft === (entry?.note || '')) return;
    const handle = setTimeout(async () => {
      setSaveState({ kind: 'saving' });
      const r = await setNote(vuln.cveId, noteDraft);
      if (r.ok) {
        setSaveState({ kind: 'saved', ts: Date.now() });
      } else {
        setSaveState({ kind: 'error', message: r.reason || 'save-failed' });
      }
    }, 600);
    return () => clearTimeout(handle);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [noteDraft, vuln.cveId]);

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

  const onWatchToggle = async () => {
    setSaveState({ kind: 'saving' });
    const r = await toggleWatch(vuln.cveId, !watched);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onSetTriage = async (next: string) => {
    setSaveState({ kind: 'saving' });
    const r = await setTriage(vuln.cveId, next);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onSetPriority = async (next: string) => {
    setSaveState({ kind: 'saving' });
    const r = await setPriority(vuln.cveId, next);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onAddTag = async (raw: string) => {
    const t = raw.trim();
    if (!t) return;
    if (tags.length >= LIMITS.TAGS_PER_CVE) return;
    setTagDraft('');
    setSaveState({ kind: 'saving' });
    const r = await addTag(vuln.cveId, t);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onRemoveTag = async (tag: string) => {
    setSaveState({ kind: 'saving' });
    const r = await removeTag(vuln.cveId, tag);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onMarkReviewed = async () => {
    setSaveState({ kind: 'saving' });
    const r = await markReviewed(vuln.cveId, publicVersion || '', changeSignature);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };
  const onArchiveToggle = async () => {
    setSaveState({ kind: 'saving' });
    const r = await archive(vuln.cveId, !archived);
    setSaveState(r.ok ? { kind: 'saved', ts: Date.now() } : { kind: 'error', message: r.reason || 'save-failed' });
  };

  const disabled = state.status === 'unavailable' || state.status === 'error';
  const noteCharsLeft = LIMITS.NOTE_MAX_CHARS - noteDraft.length;

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
            disabled={disabled || !publicVersion}
            aria-label={`Mark ${vuln.cveId} reviewed`}
            title={publicVersion ? 'Mark reviewed against the current public-intelligence view' : 'Public intelligence version unavailable'}
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
          maxLength={LIMITS.NOTE_MAX_CHARS}
          disabled={disabled}
          rows={3}
          placeholder="Add a private note — saved only on this device."
          className="focus-ring mt-1 w-full resize-y rounded-md border border-radar-border bg-radar-panel2 px-2 py-1.5 text-[12px] text-radar-text placeholder:text-radar-dim"
        />
        <div className="mt-1 flex items-center justify-between text-[10px] text-radar-dim">
          <span aria-live="polite">
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
