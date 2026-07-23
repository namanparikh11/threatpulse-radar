/**
 * V6.4 — Bulk action bar for the local workspace queue.
 *
 * Renders above the workspace panel when ≥ 1 row is
 * selected. The bar surfaces the documented bulk
 * actions: add/remove watch, set triage status, set
 * local priority, add tag, archive, restore. The bar
 * is keyboard-accessible, fully disabled while the
 * workspace is unavailable, and reports the
 * success/failure count to a polite live region.
 *
 * The bar is intentionally NOT a server-side request
 * — every action is a local IndexedDB write through
 * the workspace context.
 *
 * Destructive actions (archive, restore) require an
 * additional confirmation when the selection size
 * exceeds a documented threshold. The user can
 * proceed or cancel from the inline confirm step.
 *
 * Bulk action MAX_BATCH = 200 CVEs per click. Larger
 * selections are clipped to the first 200 in the order
 * they appear in the queue.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  Archive,
  BookmarkMinus,
  BookmarkPlus,
  Check,
  ChevronDown,
  ChevronUp,
  ListChecks,
  Tag as TagIcon,
  X,
} from 'lucide-react';
import { useWorkspace } from '../../state/WorkspaceContext';
import { TRIAGE_STATUSES, USER_PRIORITIES, LIMITS } from '../../workspace/schema.mjs';

const MAX_BATCH = 200;
const CONFIRM_THRESHOLD = 25;

type BulkOp =
  | { kind: 'watch'; on: boolean }
  | { kind: 'triage'; status: string }
  | { kind: 'priority'; priority: string }
  | { kind: 'addTag'; tag: string }
  | { kind: 'archive'; on: boolean };

interface BulkActionBarProps {
  selectedCveIds: string[];
  onClearSelection: () => void;
}

export default function BulkActionBar({
  selectedCveIds,
  onClearSelection,
}: BulkActionBarProps) {
  const {
    state,
    bulkUpdate,
    addTag,
  } = useWorkspace();
  const [open, setOpen] = useState<'watch' | 'triage' | 'priority' | 'tag' | 'archive' | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; message: string } | null>(null);
  const [pendingConfirm, setPendingConfirm] = useState<BulkOp | null>(null);
  const [pendingTag, setPendingTag] = useState('');
  const liveRegionRef = useRef<HTMLDivElement | null>(null);

  const disabled = state.status === 'unavailable' || state.status === 'error' || state.status === 'initializing';

  // Announce the latest status to assistive tech.
  useEffect(() => {
    if (status && liveRegionRef.current) {
      liveRegionRef.current.textContent = status.message;
    }
  }, [status]);

  const ids = useMemo(
    () => selectedCveIds.slice(0, MAX_BATCH),
    [selectedCveIds]
  );

  const handleBulk = useCallback(
    async (op: BulkOp) => {
      if (ids.length === 0) return;
      if (disabled) return;
      const run = async () => {
        try {
          if (op.kind === 'watch') {
            const r = await bulkUpdate(ids, { watched: op.on });
            setStatus({
              ok: r.ok,
              message: r.ok
                ? `Marked ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'} as ${op.on ? 'watched' : 'unwatched'}.`
                : 'Could not update watch state. Try again.',
            });
          } else if (op.kind === 'triage') {
            const r = await bulkUpdate(ids, { triageStatus: op.status });
            setStatus({
              ok: r.ok,
              message: r.ok
                ? `Set triage status to ${labelForStatus(op.status)} on ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'}.`
                : 'Could not update triage status. Try again.',
            });
          } else if (op.kind === 'priority') {
            const r = await bulkUpdate(ids, { userPriority: op.priority });
            setStatus({
              ok: r.ok,
              message: r.ok
                ? `Set local priority to ${labelForPriority(op.priority)} on ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'}.`
                : 'Could not update local priority. Try again.',
            });
          } else if (op.kind === 'addTag') {
            // addTag is per-cve; we iterate to keep the
            // per-CVE write queue intact.
            let updated = 0;
            for (const id of ids) {
              const r = await addTag(id, op.tag);
              if (r.ok) updated++;
            }
            setStatus({
              ok: updated > 0,
              message: `Added tag to ${updated} of ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'}.`,
            });
          } else if (op.kind === 'archive') {
            const r = await bulkUpdate(ids, { archived: op.on });
            setStatus({
              ok: r.ok,
              message: r.ok
                ? `${op.on ? 'Archived' : 'Restored'} ${ids.length} ${ids.length === 1 ? 'entry' : 'entries'}.`
                : `Could not ${op.on ? 'archive' : 'restore'} the selection. Try again.`,
            });
          }
        } catch (err) {
          setStatus({
            ok: false,
            message: err instanceof Error ? err.message : 'Could not apply the action.',
          });
        }
        onClearSelection();
        setOpen(null);
        setPendingConfirm(null);
      };
      if (
        (op.kind === 'archive' && ids.length >= CONFIRM_THRESHOLD) ||
        (op.kind === 'watch' && op.on === false && ids.length >= CONFIRM_THRESHOLD)
      ) {
        setPendingConfirm(op);
        return;
      }
      void run();
    },
    [ids, disabled, bulkUpdate, addTag, onClearSelection]
  );

  if (selectedCveIds.length === 0) return null;

  return (
    <div
      role="region"
      aria-label="Local workspace bulk action bar"
      data-testid="workspace-bulk-action-bar"
      className="panel flex flex-col gap-2 border-radar-accent/40 bg-radar-accent/5 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-center gap-2 text-radar-text">
        <ListChecks className="h-4 w-4 text-radar-accent" />
        <p>
          <span className="font-medium">
            {selectedCveIds.length.toLocaleString('en-US')}
          </span>{' '}
          {selectedCveIds.length === 1 ? 'entry' : 'entries'} selected
          {selectedCveIds.length > MAX_BATCH && (
            <span className="ml-1 text-radar-dim">
              (first {MAX_BATCH} will be applied)
            </span>
          )}
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2 sm:flex-nowrap">
        <Dropdown
          label="Watch"
          open={open === 'watch'}
          onToggle={() => setOpen(open === 'watch' ? null : 'watch')}
          disabled={disabled}
          icon={<BookmarkPlus className="h-3.5 w-3.5" />}
        >
          <button
            type="button"
            onClick={() => handleBulk({ kind: 'watch', on: true })}
            className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
          >
            <BookmarkPlus className="h-3 w-3" />
            Add to watchlist
          </button>
          <button
            type="button"
            onClick={() => handleBulk({ kind: 'watch', on: false })}
            className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
          >
            <BookmarkMinus className="h-3 w-3" />
            Remove from watchlist
          </button>
        </Dropdown>
        <Dropdown
          label="Triage"
          open={open === 'triage'}
          onToggle={() => setOpen(open === 'triage' ? null : 'triage')}
          disabled={disabled}
        >
          {TRIAGE_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => handleBulk({ kind: 'triage', status: s })}
              className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
            >
              {labelForStatus(s)}
            </button>
          ))}
        </Dropdown>
        <Dropdown
          label="Priority"
          open={open === 'priority'}
          onToggle={() => setOpen(open === 'priority' ? null : 'priority')}
          disabled={disabled}
        >
          {USER_PRIORITIES.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => handleBulk({ kind: 'priority', priority: p })}
              className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
            >
              {labelForPriority(p)}
            </button>
          ))}
        </Dropdown>
        <Dropdown
          label="Tag"
          open={open === 'tag'}
          onToggle={() => setOpen(open === 'tag' ? null : 'tag')}
          disabled={disabled}
          icon={<TagIcon className="h-3.5 w-3.5" />}
        >
          <label className="block px-2 py-1 text-[10px] uppercase tracking-wider text-radar-dim">
            Add tag (max {LIMITS.TAG_MAX_CHARS} chars, capped at {LIMITS.TAGS_PER_CVE}/entry)
          </label>
          <input
            type="text"
            value={pendingTag}
            onChange={(e) => setPendingTag(e.target.value.slice(0, LIMITS.TAG_MAX_CHARS))}
            placeholder="e.g. q3-priority"
            className="focus-ring mx-2 mb-2 w-[calc(100%-1rem)] rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            aria-label="Tag to add to every selected entry"
            maxLength={LIMITS.TAG_MAX_CHARS}
          />
          <button
            type="button"
            onClick={() => {
              if (!pendingTag.trim()) return;
              handleBulk({ kind: 'addTag', tag: pendingTag.trim() });
              setPendingTag('');
            }}
            className="focus-ring mx-2 mb-1 inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-panel2 px-2 py-1 text-xs text-radar-text hover:border-radar-accent"
            disabled={!pendingTag.trim()}
          >
            <Check className="h-3 w-3" />
            Apply
          </button>
        </Dropdown>
        <Dropdown
          label="Archive"
          open={open === 'archive'}
          onToggle={() => setOpen(open === 'archive' ? null : 'archive')}
          disabled={disabled}
          icon={<Archive className="h-3.5 w-3.5" />}
        >
          <button
            type="button"
            onClick={() => handleBulk({ kind: 'archive', on: true })}
            className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
          >
            <Archive className="h-3 w-3" />
            Archive selection
          </button>
          <button
            type="button"
            onClick={() => handleBulk({ kind: 'archive', on: false })}
            className="focus-ring flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-radar-text hover:bg-radar-panel2"
          >
            Restore selection
          </button>
        </Dropdown>
        <button
          type="button"
          onClick={onClearSelection}
          aria-label="Clear selection"
          className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      {status && (
        <div
          className={[
            'flex items-center gap-1 text-[11px]',
            status.ok ? 'text-radar-accent' : 'text-radar-warn',
          ].join(' ')}
          role="status"
          aria-live="polite"
        >
          {status.ok ? <Check className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
          {status.message}
        </div>
      )}
      {pendingConfirm && (
        <div className="basis-full">
          <ConfirmBar
            count={ids.length}
            op={pendingConfirm}
            onCancel={() => setPendingConfirm(null)}
            onConfirm={() => {
              void handleBulk(pendingConfirm);
            }}
          />
        </div>
      )}
      <div ref={liveRegionRef} className="sr-only" aria-live="polite" />
    </div>
  );
}

function ConfirmBar({
  count,
  op,
  onCancel,
  onConfirm,
}: {
  count: number;
  op: BulkOp;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const verb =
    op.kind === 'archive'
      ? op.on
        ? 'archive'
        : 'restore'
      : op.kind === 'watch'
        ? 'unwatch'
        : 'modify';
  return (
    <div className="mt-2 flex flex-col gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-3 py-2 text-[11px] sm:flex-row sm:items-center sm:justify-between">
      <p className="text-radar-text">
        About to {verb} <strong>{count.toLocaleString('en-US')}</strong>{' '}
        {count === 1 ? 'entry' : 'entries'}. This affects only your local
        workspace; the public dataset is not modified.
      </p>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-muted hover:border-radar-accent/40"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-panel2 px-2 py-1 text-xs text-radar-warn hover:border-radar-warn"
        >
          Confirm
        </button>
      </div>
    </div>
  );
}

function Dropdown({
  label,
  open,
  onToggle,
  children,
  disabled,
  icon,
}: {
  label: string;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
  disabled?: boolean;
  icon?: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!ref.current) return;
      if (e.target instanceof Node && ref.current.contains(e.target)) return;
      onToggle();
    }
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open, onToggle]);
  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={onToggle}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-accent/40 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {icon}
        {label}
        {open ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-30 mt-1 w-48 rounded-md border border-radar-border bg-radar-panel p-2 shadow-lg"
        >
          {children}
        </div>
      )}
    </div>
  );
}

function labelForStatus(s: string): string {
  switch (s) {
    case 'unreviewed': return 'Unreviewed';
    case 'reviewing': return 'Reviewing';
    case 'action-required': return 'Action required';
    case 'mitigating': return 'Mitigating';
    case 'resolved': return 'Resolved';
    case 'accepted-risk': return 'Accepted risk';
    case 'not-applicable': return 'Not applicable';
    default: return s;
  }
}

function labelForPriority(p: string): string {
  switch (p) {
    case 'none': return 'No local priority';
    case 'low': return 'Low';
    case 'medium': return 'Medium';
    case 'high': return 'High';
    case 'urgent': return 'Urgent';
    default: return p;
  }
}
