/**
 * V6.5 — Report builder dialog.
 *
 * Application-level dialog. Renders the builder form,
 * builds the snapshot, computes the integrity
 * checksum, and shows the preview. The export action
 * is wired to the parent (the parent owns the export
 * helpers) so the builder never imports the exporters
 * directly.
 *
 * The dialog is fully keyboard-accessible, traps
 * focus, restores focus on close, and renders React
 * text only.
 *
 * The "build" step uses the same flush + snapshot
 * pattern as the standalone generator. If the workspace
 * has pending writes that cannot be flushed, the
 * build step surfaces a sanitized error and the
 * dialog stays open.
 *
 * The builder NEVER:
 *   - reads the network
 *   - writes to the URL / history
 *   - logs to the console
 *   - mutates the workspace
 *   - mutates the public dataset
 *   - calls `dangerouslySetInnerHTML`
 */

import { useCallback, useMemo, useState } from 'react';
import { AlertTriangle, FileText, ShieldAlert } from 'lucide-react';
import { useWorkspace } from '../../state/WorkspaceContext';
import { useRemediation } from '../../state/RemediationContext';
import { REPORT_LIMITS, REPORT_TYPES, REDACTION_MODES, normaliseCveId } from '../../reports/schema.mjs';
import { buildReportSnapshot } from '../../reports/snapshot.mjs';
import { buildReport } from '../../reports/templates.mjs';
import { computeIntegrity } from '../../reports/integrity.mjs';
import ReportDialogShell from './ReportDialogShell';
import ReportPreview from './ReportPreview';

export interface ReportBuilderProps {
  /** Initial selection of CVE ids. The dialog lets the
   *  operator override the selection before generation. */
  initialCveIds: string[];
  /** Initial report type. */
  initialReportType?: string;
  /** Initial title. */
  initialTitle?: string;
  /** V6.1 public-intelligence metadata block. The
   *  builder uses it to stamp the report's
   *  `publicIntelligence` section. The builder never
   *  re-fetches the network; the value is whatever the
   *  parent already loaded. */
  publicMeta?: any | null;
  /** V6.1 public vulnerability list. The builder uses
   *  it to populate the public CVE records in the
   *  snapshot. */
  publicVulns?: any[] | null;
  /** When the dialog emits a "built" report, the parent
   *  is responsible for triggering the actual export. */
  onClose: () => void;
  /** Called with the built (integrity-stamped) report
   *  + the selected export format. The parent invokes
   *  the exporter and the download helper. */
  onExport?: (report: any, format: 'markdown' | 'html' | 'print' | 'json') => void;
  /** V6.5: open the report history dialog. The parent
   *  closes the builder dialog and opens the history
   *  dialog. The builder never touches history itself. */
  onOpenHistory?: () => void;
  /** V6.5: open the verify/compare dialog for a JSON
   *  report file. The parent closes the builder dialog
   *  and opens the verifier. */
  onOpenVerify?: (mode: 'verify' | 'compare') => void;
}

export default function ReportBuilder({
  initialCveIds,
  initialReportType = 'defender-daily-briefing',
  initialTitle = 'Defender Daily Briefing',
  publicMeta = null,
  publicVulns = null,
  onClose,
  onExport,
  onOpenHistory,
  onOpenVerify,
}: ReportBuilderProps) {
  const workspace = useWorkspace();
  const remediation = useRemediation();

  const [reportType, setReportType] = useState(initialReportType);
  const [title, setTitle] = useState(initialTitle);
  const [cveIds, setCveIds] = useState(() => initialCveIds.map((c) => normaliseCveId(c) || '').filter(Boolean));
  const [includePrivateNotes, setIncludePrivateNotes] = useState(false);
  const [includeLocalTags, setIncludeLocalTags] = useState(true);
  const [includeResolved, setIncludeResolved] = useState(false);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [includeRemediationSummary, setIncludeRemediationSummary] = useState(false);
  const [redactionMode, setRedactionMode] = useState('exclude-private-notes');
  const [exportFormat, setExportFormat] = useState<'markdown' | 'html' | 'print' | 'json'>('markdown');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<any | null>(null);

  // V6.7: counts-only local remediation summary. Never
  // contains owner labels / plan / task / evidence / fingerprint /
  // blocker content. Opt-in only.
  const remediationSummary = useMemo(() => {
    if (!includeRemediationSummary) return null;
    const counts = remediation.countByStatus();
    const plans = remediation.state.plans || [];
    const now = Date.now();
    const overdue = plans.filter((p: any) => {
      if (p.archived) return false;
      if (p.status === 'completed' || p.status === 'cancelled' || p.status === 'accepted-risk') return false;
      if (typeof p.dueAt !== 'string' || p.dueAt.length === 0) return false;
      return Date.parse(p.dueAt) < now;
    }).length;
    const validationPending = plans.filter((p: any) => !p.archived && (p.status === 'validation-pending' || p.validationStatus === 'pending')).length;
    const completedLocal = (counts.completed || 0);
    const acceptedRisk = (counts['accepted-risk'] || 0);
    const active = plans.filter((p: any) => !p.archived && p.status !== 'completed' && p.status !== 'cancelled' && p.status !== 'accepted-risk').length;
    const draft = (counts.draft || 0);
    const blocked = (counts.blocked || 0);
    const archived = plans.filter((p: any) => p.archived).length;
    const brokenLedger = Object.values(remediation.state.ledgerVerification.perPlan || {}).filter((v: any) => v && !v.ok).length;
    return {
      activePlanCount: active,
      draftPlanCount: draft,
      blockedPlanCount: blocked,
      overduePlanCount: overdue,
      validationPendingCount: validationPending,
      completedLocalCount: completedLocal,
      acceptedRiskCount: acceptedRisk,
      archivedPlanCount: archived,
      brokenLedgerCount: brokenLedger,
    };
  }, [includeRemediationSummary, remediation.state.plans, remediation.state.ledgerVerification.perPlan, remediation]);

  // The CVE list is bounded to MAX_CVES.
  const cveIdList = useMemo(() => cveIds.slice(0, REPORT_LIMITS.MAX_CVES), [cveIds]);
  const cveOverLimit = cveIds.length > REPORT_LIMITS.MAX_CVES;

  const handleRemove = useCallback((cve: string) => {
    setCveIds((prev) => prev.filter((c) => c !== cve));
  }, []);

  const handleAddFromInput = useCallback((raw: string) => {
    const id = normaliseCveId(raw);
    if (!id) return;
    setCveIds((prev) => prev.includes(id) ? prev : [...prev, id].slice(0, REPORT_LIMITS.MAX_CVES + 1));
  }, []);

  // Build a coherent snapshot + report.
  const handleBuild = useCallback(async () => {
    setError(null);
    setReport(null);
    if (cveIdList.length === 0) {
      setError('Select at least one CVE to include in the report.');
      return;
    }
    if (workspace.state.status === 'unavailable' || workspace.state.status === 'error') {
      setError('Local workspace is unavailable; cannot generate a report that depends on the workspace.');
      return;
    }
    setBusy(true);
    try {
      const snapshot = await buildReportSnapshot({
        publicMeta: publicMeta || null,
        vulns: Array.isArray(publicVulns) ? publicVulns : [],
        entriesByCve: workspace.state.entriesByCve,
        selection: {
          cveIds: cveIdList,
          includePrivateNotes,
          includeLocalTags,
          includeResolved,
          includeArchived,
        },
        flushPendingWrites: workspace.flushPendingWrites,
        hasPendingWrites: workspace.hasPendingWrites,
        options: {
          applicationVersion: 'v6.7',
          localRemediationSummary: remediationSummary,
        },
      });
      const built = buildReport({
        reportId: '',
        reportType,
        title: title || 'Untitled report',
        generatedAt: new Date().toISOString(),
        applicationVersion: 'v6.7',
        snapshot,
        mode: redactionMode,
        includePrivateNotes: includePrivateNotes && redactionMode !== 'exclude-private-notes' && redactionMode !== 'exclude-all-user-text' && redactionMode !== 'identifiers-only',
        includeLocalTags,
      });
      const integ = await computeIntegrity(built);
      built.integrity = integ;
      built.reportId = `rpt-${Date.now()}-${Math.floor(Math.random() * 0xffffff).toString(16)}`;
      setReport(built);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'unknown-error';
      setError(`Could not build the report: ${msg}`);
    } finally {
      setBusy(false);
    }
  }, [cveIdList, workspace, includePrivateNotes, includeLocalTags, includeResolved, includeArchived, redactionMode, reportType, title, remediationSummary]);

  const handleExport = useCallback(() => {
    if (!report || !onExport) return;
    onExport(report, exportFormat);
  }, [report, onExport, exportFormat]);

  // The number of local notes the report will include
  // is recomputed against the live entriesByCve so the
  // warning stays current as the operator toggles
  // workspace entries.
  const liveNotesCount = useMemo(() => {
    let n = 0;
    for (const c of cveIdList) {
      const e = workspace.state.entriesByCve[c];
      if (e && typeof e.note === 'string' && e.note.length > 0) n++;
    }
    return n;
  }, [cveIdList, workspace.state.entriesByCve]);

  return (
    <ReportDialogShell title="Build a local report" onClose={onClose}>
      <p className="text-xs text-radar-muted" data-testid="report-builder-privacy-preamble">
        Reports are generated entirely in this browser. They may contain private notes or internal workflow information. Review the preview before exporting.
      </p>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
        <label className="block">
          <span className="text-[11px] text-radar-muted">Report type</span>
          <select
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            aria-label="Report type"
          >
            {REPORT_TYPES.map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Title</span>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value.slice(0, REPORT_LIMITS.MAX_TITLE_CHARS))}
            maxLength={REPORT_LIMITS.MAX_TITLE_CHARS}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            aria-label="Report title"
          />
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Redaction mode</span>
          <select
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            value={redactionMode}
            onChange={(e) => setRedactionMode(e.target.value)}
            aria-label="Redaction mode"
          >
            {REDACTION_MODES.map((m) => (
              <option key={m.id} value={m.id}>{m.label}</option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Export format</span>
          <select
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-xs text-radar-text"
            value={exportFormat}
            onChange={(e) => setExportFormat(e.target.value as any)}
            aria-label="Export format"
          >
            <option value="markdown">Markdown (.md)</option>
            <option value="html">Standalone HTML (.html)</option>
            <option value="print">Print-optimized HTML (Save as PDF)</option>
            <option value="json">Strict JSON bundle (.json)</option>
          </select>
        </label>
      </div>

      <fieldset className="mt-3 rounded-md border border-radar-border bg-radar-panel2/30 p-3">
        <legend className="px-1 text-[11px] text-radar-muted">Selection</legend>
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-0.5 text-[11px] text-radar-text">
            {cveIdList.length} / {REPORT_LIMITS.MAX_CVES} CVEs
          </span>
          {cveOverLimit && (
            <span className="inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-0.5 text-[11px] text-radar-warn">
              <AlertTriangle className="h-3 w-3" />
              Selection exceeds limit; the first {REPORT_LIMITS.MAX_CVES} will be used.
            </span>
          )}
        </div>
        <div className="mt-2 max-h-32 overflow-y-auto rounded-md border border-radar-border/40 bg-radar-panel2/40 p-2">
          {cveIdList.length === 0 ? (
            <p className="text-[11px] text-radar-dim">No CVEs selected. Add at least one to build a report.</p>
          ) : (
            <ul className="flex flex-wrap gap-1" role="list">
              {cveIdList.map((c) => (
                <li key={c} className="inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel px-1.5 py-0.5 text-[11px] text-radar-text">
                  <span className="font-mono">{c}</span>
                  <button
                    type="button"
                    onClick={() => handleRemove(c)}
                    aria-label={`Remove ${c} from selection`}
                    className="focus-ring -mr-1 ml-1 inline-flex h-3.5 w-3.5 items-center justify-center rounded-full text-radar-dim hover:text-radar-text"
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <form
          className="mt-2 flex items-center gap-2"
          onSubmit={(e) => { e.preventDefault(); const el = (e.currentTarget.elements.namedItem('addCve') as HTMLInputElement | null); if (el && el.value) { handleAddFromInput(el.value); el.value = ''; } }}
        >
          <label htmlFor="add-cve" className="text-[11px] text-radar-muted">Add CVE</label>
          <input
            id="add-cve"
            name="addCve"
            type="text"
            placeholder="CVE-YYYY-NNNN"
            className="focus-ring w-44 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text placeholder:text-radar-dim"
            aria-label="Add a CVE id to the selection"
          />
          <button
            type="submit"
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text transition hover:border-radar-accent/40"
          >
            Add
          </button>
        </form>
      </fieldset>

      <fieldset className="mt-3 rounded-md border border-radar-border bg-radar-panel2/30 p-3">
        <legend className="px-1 text-[11px] text-radar-muted">Local workspace</legend>
        <div className="flex flex-wrap items-center gap-3 text-[12px] text-radar-text">
          <label className="inline-flex items-center gap-1">
            <input
              type="checkbox"
              checked={includePrivateNotes}
              onChange={(e) => setIncludePrivateNotes(e.target.checked)}
              className="focus-ring h-3.5 w-3.5"
              data-testid="report-builder-include-notes"
            />
            <span>Include private notes (off by default)</span>
          </label>
          <label className="inline-flex items-center gap-1">
            <input
              type="checkbox"
              checked={includeLocalTags}
              onChange={(e) => setIncludeLocalTags(e.target.checked)}
              className="focus-ring h-3.5 w-3.5"
            />
            <span>Include local tags</span>
          </label>
          <label className="inline-flex items-center gap-1">
            <input
              type="checkbox"
              checked={includeResolved}
              onChange={(e) => setIncludeResolved(e.target.checked)}
              className="focus-ring h-3.5 w-3.5"
            />
            <span>Include resolved entries</span>
          </label>
          <label className="inline-flex items-center gap-1">
            <input
              type="checkbox"
              checked={includeArchived}
              onChange={(e) => setIncludeArchived(e.target.checked)}
              className="focus-ring h-3.5 w-3.5"
            />
            <span>Include archived entries</span>
          </label>
          <label className="inline-flex items-center gap-1" title="Adds a counts-only local remediation summary. Never includes owner labels, plan content, task content, evidence content, file fingerprints, blocker reasons, validation notes, or actor labels.">
            <input
              type="checkbox"
              checked={includeRemediationSummary}
              onChange={(e) => setIncludeRemediationSummary(e.target.checked)}
              className="focus-ring h-3.5 w-3.5"
              data-testid="report-builder-include-remediation-summary"
            />
            <span>Include local remediation summary (counts only, opt-in)</span>
          </label>
        </div>
        {includePrivateNotes && (
          <p
            role="alert"
            aria-live="polite"
            className="mt-2 inline-flex items-center gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[11px] text-radar-warn"
            data-testid="report-builder-notes-warning"
          >
            <ShieldAlert className="h-3 w-3" />
            Local privacy warning: this report will include {liveNotesCount} private note{liveNotesCount === 1 ? '' : 's'} from your workspace. Treat the exported file as sensitive.
          </p>
        )}
      </fieldset>

      {error && (
        <p role="alert" aria-live="polite" className="mt-3 inline-flex items-center gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="report-builder-error">
          <AlertTriangle className="h-3 w-3" />
          {error}
        </p>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
        <div className="text-[10px] text-radar-dim">
          Web Crypto is used for the SHA-256 integrity checksum. No remote hashing service is contacted.
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onClose}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
          >
            Cancel
          </button>
          {onOpenHistory && (
            <button
              type="button"
              onClick={onOpenHistory}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid="report-builder-open-history"
              title="Open local report history"
            >
              History
            </button>
          )}
          {onOpenVerify && (
            <button
              type="button"
              onClick={() => onOpenVerify('verify')}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
              data-testid="report-builder-open-verify"
              title="Verify or compare JSON report files"
            >
              Verify…
            </button>
          )}
          <button
            type="button"
            onClick={handleBuild}
            disabled={busy || cveIdList.length === 0}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-3 py-1.5 text-xs text-radar-accent transition hover:border-radar-accent disabled:opacity-50 disabled:cursor-not-allowed"
            data-testid="report-builder-build"
          >
            <FileText className="h-3.5 w-3.5" />
            {busy ? 'Building…' : 'Build preview'}
          </button>
          <button
            type="button"
            onClick={handleExport}
            disabled={!report}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed"
            data-testid="report-builder-export"
          >
            Export {exportFormat.toUpperCase()}
          </button>
        </div>
      </div>

      <div className="mt-4">
        {report ? (
          <ReportPreview report={report} />
        ) : (
          <p className="rounded-md border border-dashed border-radar-border bg-radar-panel2/40 px-3 py-3 text-center text-[11px] text-radar-dim">
            Click <strong>Build preview</strong> to render the report from the frozen snapshot.
          </p>
        )}
      </div>
    </ReportDialogShell>
  );
}
