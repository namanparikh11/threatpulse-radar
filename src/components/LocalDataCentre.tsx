/**
 * V6.8 — Local Data Control Centre.
 *
 * A single, compact surface that summarizes every
 * local-only dataset (workspace, environment,
 * remediation, report history) and exposes
 * per-dataset export and clear actions. The panel
 * intentionally keeps each dataset's clear action
 * independent so a destructive action on one
 * dataset can never silently clear another.
 *
 * The control centre never:
 *   - writes to the URL or history
 *   - logs private content to the console
 *   - claims a clear action is reversible
 *   - combines multiple dataset clears into a
 *     single destructive action
 *
 * The control centre is read-only by default. The
 * clear / export actions live behind buttons that
 * surface a confirmation step (a local accessible
 * dialog) before any destructive mutation. A
 * browser-native `window.confirm` is never used.
 */
import { useCallback, useMemo, useState } from 'react';
import { Database, Download, Trash2 } from 'lucide-react';
import { useWorkspace } from '../state/WorkspaceContext';
import { useEnvironment } from '../state/EnvironmentContext';
import { useRemediation } from '../state/RemediationContext';
import { ClearConfirmDialog } from './ClearConfirmDialog';
import { quickReport } from '../state/diagnostics';

interface LocalDataCentreProps {
  onExportWorkspace?(): Promise<void> | void;
  onExportEnvironment?(): Promise<void> | void;
  onExportRemediation?(): Promise<void> | void;
  onClearWorkspace?(): Promise<{ ok: boolean; reason?: string }>;
  onClearEnvironment?(): Promise<{ ok: boolean; reason?: string }>;
  onClearRemediation?(): Promise<{ ok: boolean; reason?: string }>;
  onClearReportHistory?(): Promise<{ ok: boolean; reason?: string }>;
  reportHistoryCount?: number;
}

type ConfirmKind = 'workspace' | 'environment' | 'remediation' | 'history' | null;

export function LocalDataCentre(props: LocalDataCentreProps) {
  const workspace = useWorkspace();
  const environment = useEnvironment();
  const remediation = useRemediation();
  const [confirm, setConfirm] = useState<ConfirmKind>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<ConfirmKind | null>(null);

  const quick = useMemo(
    () => quickReport({ workspaceCtx: workspace, environmentCtx: environment, remediationCtx: remediation }),
    [workspace, environment, remediation],
  );

  const storageKind = useMemo(() => {
    if (workspace.state.status === 'unavailable' && environment.state.status === 'unavailable' && remediation.state.status === 'unavailable') return 'unavailable';
    if (workspace.state.status === 'session-only' || environment.state.status === 'session-only' || remediation.state.status === 'session-only') return 'session';
    return 'persistent';
  }, [workspace.state.status, environment.state.status, remediation.state.status]);

  const onExport = useCallback(async (kind: 'workspace' | 'environment' | 'remediation') => {
    setError(null);
    try {
      if (kind === 'workspace' && props.onExportWorkspace) await props.onExportWorkspace();
      if (kind === 'environment' && props.onExportEnvironment) await props.onExportEnvironment();
      if (kind === 'remediation' && props.onExportRemediation) await props.onExportRemediation();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'export-failed');
    }
  }, [props]);

  const onConfirmClear = useCallback(async () => {
    if (!confirm) return;
    setBusy(confirm);
    setError(null);
    try {
      let r: { ok: boolean; reason?: string } | null = null;
      if (confirm === 'workspace' && props.onClearWorkspace) r = await props.onClearWorkspace();
      if (confirm === 'environment' && props.onClearEnvironment) r = await props.onClearEnvironment();
      if (confirm === 'remediation' && props.onClearRemediation) r = await props.onClearRemediation();
      if (confirm === 'history' && props.onClearReportHistory) r = await props.onClearReportHistory();
      if (r && !r.ok) setError(r.reason || 'clear-failed');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'clear-failed');
    } finally {
      setBusy(null);
      setConfirm(null);
    }
  }, [confirm, props]);

  const exportFirst = confirm === 'workspace' || confirm === 'environment' || confirm === 'remediation' || confirm === 'history';
  const count = (n: number, label: string) => `${n} ${label}${n === 1 ? '' : 's'}`;

  return (
    <section className="panel space-y-3 px-4 py-4" aria-label="Local data centre" data-testid="local-data-centre">
      <header className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-radar-text">
          <Database className="h-4 w-4 text-radar-accent" /> Local data control centre
        </h2>
        <p className="text-[11px] text-radar-muted">
          A compact view of every dataset stored in this browser. Each dataset is independent — clearing one never
          touches another. Always export first if you may need to restore.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <DatasetCard
          title="Workspace"
          description="Local CVE triage, notes, and tags"
          entries={[
            (quick.workspace.entryCount || 0) === 1 ? '1 workspace entry' : `${quick.workspace.entryCount || 0} workspace entries`,
            `${count(0, 'correlated component')}`,
            'status: ' + (workspace.state.status || 'unknown'),
          ]}
          dataTestId="local-data-centre-workspace"
          onExport={props.onExportWorkspace ? () => onExport('workspace') : null}
          onClear={() => setConfirm('workspace')}
        />
        <DatasetCard
          title="My Environment"
          description="Local assets, SBOMs, correlations, reviews"
          entries={[
            `${count(quick.environment.assetCount || 0, 'asset')}`,
            'correlations: ' + (Object.keys(environment.state.correlationsByInventory || {}).length),
            'status: ' + (environment.state.status || 'unknown'),
          ]}
          dataTestId="local-data-centre-environment"
          onExport={props.onExportEnvironment ? () => onExport('environment') : null}
          onClear={() => setConfirm('environment')}
        />
        <DatasetCard
          title="Remediation"
          description="Local plans, tasks, evidence, ledger"
          entries={[
            `${count(quick.remediation.planCount || 0, 'plan')}`,
            'evidence: ' + (Object.values(remediation.state.evidenceByPlan || {}).reduce((n: number, l: any) => n + (Array.isArray(l) ? l.length : 0), 0)),
            'status: ' + (remediation.state.status || 'unknown'),
          ]}
          dataTestId="local-data-centre-remediation"
          onExport={props.onExportRemediation ? () => onExport('remediation') : null}
          onClear={() => setConfirm('remediation')}
        />
        <DatasetCard
          title="Report history"
          description="Summary-only record of generated reports"
          entries={[
            `${count(props.reportHistoryCount || 0, 'report')}`,
            'storage: ' + storageKind,
          ]}
          dataTestId="local-data-centre-history"
          onExport={null}
          onClear={props.onClearReportHistory ? () => setConfirm('history') : null}
        />
      </div>

      <p className="text-[10px] text-radar-dim">
        Storage mode: <span className="font-mono">{storageKind}</span>. Browser private-mode sessions may
        not survive a tab close. Export-first guidance applies to every clear action.
      </p>

      {error && (
        <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="local-data-centre-error">
          {error}
        </p>
      )}

      {confirm && (
        <ClearConfirmDialog
          open={true}
          kind={confirm}
          exportFirst={exportFirst}
          busy={busy === confirm}
          onCancel={() => setConfirm(null)}
          onConfirm={onConfirmClear}
        />
      )}
    </section>
  );
}

function DatasetCard({ title, description, entries, dataTestId, onExport, onClear }: {
  title: string;
  description: string;
  entries: string[];
  dataTestId: string;
  onExport: (() => void) | null;
  onClear: (() => void) | null;
}) {
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-3 text-[11px]" data-testid={dataTestId}>
      <p className="text-[12px] font-semibold text-radar-text">{title}</p>
      <p className="text-[10px] text-radar-dim">{description}</p>
      <ul className="mt-2 space-y-0.5 text-radar-muted">
        {entries.map((e, i) => <li key={i}>{e}</li>)}
      </ul>
      <div className="mt-3 flex flex-wrap items-center gap-1">
        {onExport ? (
          <button
            type="button"
            onClick={onExport}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
            data-testid={`${dataTestId}-export`}
          >
            <Download className="h-3 w-3" /> Export
          </button>
        ) : null}
        {onClear ? (
          <button
            type="button"
            onClick={onClear}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[10px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn"
            data-testid={`${dataTestId}-clear`}
          >
            <Trash2 className="h-3 w-3" /> Clear
          </button>
        ) : null}
      </div>
    </div>
  );
}
