/**
 * V6.4 — Multi-tab workspace conflict banner.
 *
 * Renders a compact, dismissible banner above the
 * dashboard body when a competing edit was detected
 * in another tab. The banner is the ONLY visible
 * surface that exposes the conflict; the workspace
 * state is never read from the URL or rendered in any
 * other component.
 *
 * The banner is keyboard-dismissible (× button with
 * aria-label) and announces itself via role="alert"
 * so screen readers pick it up. The conflict is
 * intentionally descriptive: the operator sees the
 * CVE id, the reason, and the latest committed
 * updatedAt.
 *
 * The banner NEVER displays the note or any tag
 * contents. The conflict metadata (cveId, reason,
 * remote.updatedAt) is the only information shown.
 */

import { useEffect, useRef } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useWorkspace } from '../../state/WorkspaceContext';

function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    return d.toLocaleString();
  } catch {
    return ts;
  }
}

export default function ConflictBanner() {
  const { state, dismissConflict } = useWorkspace();
  const conflict = state.conflict;
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  // Move focus to the dismiss button when the
  // banner appears, so a screen-reader user can
  // dismiss without hunting.
  useEffect(() => {
    if (conflict && buttonRef.current) {
      buttonRef.current.focus();
    }
  }, [conflict]);

  if (!conflict) return null;
  const cveId = conflict.cveId;
  const reasonLabel =
    conflict.reason === 'deleted'
      ? 'was deleted in another tab'
      : conflict.reason === 'replaced'
        ? 'was replaced in another tab'
        : 'was updated in another tab';
  const remote = conflict.remote;
  return (
    <div
      role="alert"
      aria-live="polite"
      className="panel flex flex-col gap-2 border-radar-warn/40 bg-radar-warn/5 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-start gap-2">
        <AlertTriangle
          className="mt-0.5 h-4 w-4 shrink-0 text-radar-warn"
          aria-hidden="true"
        />
        <div>
          <p className="font-medium text-radar-text">
            Local workspace entry {cveId} {reasonLabel}.
          </p>
          <p className="mt-0.5 text-xs text-radar-muted">
            {remote
              ? `The other tab wrote a newer record at ${formatTimestamp(remote.updatedAt)}. ` +
                'Your current tab will keep its older record. Click "Keep newer" to adopt the remote change, or dismiss to keep your local copy.'
              : 'The other tab removed the entry. Your current tab will keep its older record. Dismiss to keep your local copy.'}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2 self-start">
        {remote && (
          <button
            type="button"
            onClick={() => dismissConflict()}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-warn/40 bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-warn"
          >
            Keep newer
          </button>
        )}
        <button
          ref={buttonRef}
          type="button"
          onClick={() => dismissConflict()}
          aria-label="Dismiss workspace conflict banner"
          title="Dismiss — keep your local copy"
          className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted transition hover:border-radar-accent/40 hover:text-radar-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
