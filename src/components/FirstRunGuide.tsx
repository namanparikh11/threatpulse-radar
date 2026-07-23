/**
 * V6.8 — Compact first-run guide.
 *
 * A small, collapsible surface that surfaces the
 * minimal first-use steps the operator needs to
 * understand ThreatPulse Radar. The guide:
 *   - does not overwhelm the main dashboard
 *   - does not persist fake provider data
 *   - collapses to a single line once dismissed
 *   - explains the local-only storage boundary
 *   - points to the local documentation
 *
 * The guide is purely informational. The first-use
 * state lives in component state and never enters
 * the URL or the React state machine.
 */
import { useState } from 'react';
import { ChevronDown, ChevronUp, Sparkles, X } from 'lucide-react';

interface FirstRunGuideProps {
  hasWorkspaceEntries?: boolean;
  hasEnvironment?: boolean;
  hasRemediation?: boolean;
  onDismiss?(): void;
}

export function FirstRunGuide({ hasWorkspaceEntries, hasEnvironment, hasRemediation, onDismiss }: FirstRunGuideProps) {
  const [expanded, setExpanded] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;
  // Once the operator has at least one local entry
  // we still render but in compact form, with a
  // dismiss option.
  const allUsed = Boolean(hasWorkspaceEntries) && Boolean(hasEnvironment) && Boolean(hasRemediation);
  return (
    <section
      className="panel space-y-2 px-4 py-3 text-[11px] text-radar-muted"
      aria-label="First-run guide"
      data-testid="first-run-guide"
    >
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-radar-accent" />
          <span className="text-radar-text">
            {allUsed ? 'Local-only data summary' : 'A quick tour of the local surfaces'}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            data-testid="first-run-toggle"
          >
            {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            {expanded ? 'Less' : 'More'}
          </button>
          {onDismiss && (
            <button
              type="button"
              onClick={() => { setDismissed(true); onDismiss(); }}
              aria-label="Dismiss first-run guide"
              className="focus-ring inline-flex h-6 w-6 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid="first-run-dismiss"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>
      </header>
      <p className="text-radar-muted">
        Public intelligence (CISA KEV, NVD CVSS, FIRST EPSS, GitHub Advisory, OSV) loads on the main table.
        The local surfaces — workspace, My Environment, remediation, report history — store data only in this browser.
      </p>
      {expanded && (
        <ol className="list-decimal pl-5 text-radar-text">
          <li>
            <span className="text-radar-muted">Watch a CVE</span> from the table or drawer to add it to your local
            workspace. The workspace entry never leaves this device.
          </li>
          <li>
            <span className="text-radar-muted">Register a local asset</span> in My Environment and import a
            supported SBOM. The importer runs entirely locally and surfaces a public correlation only for
            components that match an advisory identity.
          </li>
          <li>
            <span className="text-radar-muted">Open a correlation</span> in the queue and review it locally.
            Review notes are private. Mark "remediation planned" when a plan exists.
          </li>
          <li>
            <span className="text-radar-muted">Create a remediation plan</span> from the CVE drawer or the
            correlation queue. Add tasks, attach evidence, fingerprint a local file (no upload).
          </li>
          <li>
            <span className="text-radar-muted">Export often.</span> Each local surface has its own backup.
            Combine them before clearing if you want a complete snapshot.
          </li>
        </ol>
      )}
    </section>
  );
}
