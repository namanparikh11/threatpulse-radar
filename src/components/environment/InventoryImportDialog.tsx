/**
 * V6.6 — Inventory import dialog.
 *
 * The dialog is a three-step flow:
 *   1. File selection (one-click file picker for
 *      a supported SBOM / inventory file).
 *   2. Dry-run preview showing the detected format,
 *      source version, component count, warnings,
 *      and rejected-row count. The operator MUST
 *      confirm before the apply step runs.
 *   3. Apply: the EnvironmentContext applies the
 *      inventory + components + correlation in a
 *      single atomic step. The dialog shows the
 *      component count + correlation summary.
 *
 * The dialog NEVER:
 *   - calls the network
 *   - writes to the URL / history
 *   - logs private values to the console
 *   - mutates the workspace / public corpus
 */

import { useCallback, useState } from 'react';
import { AlertTriangle, FileSearch, Upload } from 'lucide-react';
import { useEnvironment } from '../../state/EnvironmentContext';
import { detectFormat, parseImport } from '../../environment/import.mjs';
import { ASSET_LIMITS } from '../../environment/schema.mjs';
import ReportDialogShell from '../reports/ReportDialogShell';

export interface InventoryImportDialogProps {
  assets: any[];
  onClose: () => void;
}

export default function InventoryImportDialog({ assets, onClose }: InventoryImportDialogProps) {
  const env = useEnvironment();
  const [assetId, setAssetId] = useState(assets[0]?.assetId || '');
  const [stage, setStage] = useState<'pick' | 'preview' | 'apply'>('pick');
  const [fileName, setFileName] = useState<string | null>(null);
  const [text, setText] = useState<string>('');
  const [detected, setDetected] = useState<{ format: string; sourceVersion: string | null } | null>(null);
  const [parsed, setParsed] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ componentCount: number; correlationCount: number } | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setError(null);
    setResult(null);
    if (file.size > ASSET_LIMITS.MAX_IMPORT_BYTES) {
      setError(`File is larger than ${ASSET_LIMITS.MAX_IMPORT_BYTES} bytes.`);
      return;
    }
    setBusy(true);
    try {
      const t = await file.text();
      setFileName(file.name);
      setText(t);
      const d = detectFormat(t);
      if (!d.format) {
        setError(`Unrecognised format: ${d.reason || 'unknown'}`);
        setStage('pick');
        return;
      }
      setDetected({ format: d.format, sourceVersion: d.sourceVersion });
      const r = parseImport(t, { assetId, inventoryId: 'preview-' + Date.now() });
      if (!r.ok) {
        setError(`Could not parse: ${r.reason}`);
        setStage('pick');
        return;
      }
      setParsed(r.result);
      setStage('preview');
    } finally {
      setBusy(false);
    }
  }, [assetId]);

  const handleApply = useCallback(async () => {
    if (!parsed) return;
    setError(null);
    setBusy(true);
    try {
      const r = await env.importInventoryApply(assetId, parsed, { publicVulns: [], publicMeta: null });
      if (!r.ok) {
        setError(`Could not apply inventory: ${r.reason}`);
        return;
      }
      setResult({ componentCount: r.componentCount, correlationCount: r.correlations.length });
      setStage('apply');
    } finally {
      setBusy(false);
    }
  }, [assetId, parsed, env]);

  return (
    <ReportDialogShell title="Import inventory" onClose={onClose}>
      <p className="text-[11px] text-radar-muted">
        Supported formats: CycloneDX 1.4/1.5/1.6 JSON, SPDX 2.3 JSON, ThreatPulse local inventory JSON, or a documented CSV. The file is parsed in the browser; nothing is uploaded.
      </p>

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
        <label className="block">
          <span className="text-[11px] text-radar-muted">Asset</span>
          <select
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            data-testid="inventory-import-asset"
            disabled={stage !== 'pick'}
          >
            {assets.map((a) => <option key={a.assetId} value={a.assetId}>{a.name}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">File</span>
          <input
            type="file"
            accept=".json,.csv,application/json,text/csv"
            onChange={(e) => {
              const f = e.target.files && e.target.files[0];
              if (f) void handleFile(f);
            }}
            className="focus-ring mt-1 block w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text file:mr-2 file:rounded-md file:border-0 file:bg-radar-panel file:px-2 file:py-1 file:text-radar-text"
            disabled={busy}
            data-testid="inventory-import-file"
          />
        </label>
      </div>

      {stage === 'preview' && parsed && (
        <div className="mt-3 rounded-md border border-radar-border bg-radar-panel2/30 p-3 text-[12px] text-radar-text" data-testid="inventory-import-preview">
          <p><strong>Detected format:</strong> {detected?.format || 'unknown'}{detected?.sourceVersion ? ` (version ${detected.sourceVersion})` : ''}</p>
          <p><strong>File:</strong> <span className="font-mono">{fileName}</span> ({text.length} bytes)</p>
          <p><strong>Components:</strong> {parsed.components.length}</p>
          <p><strong>Rejected rows:</strong> {parsed.rejected || 0}</p>
          {Array.isArray(parsed.warnings) && parsed.warnings.length > 0 && (
            <ul className="mt-2 list-disc space-y-0.5 pl-5 text-radar-warn">
              {parsed.warnings.map((w: string, i: number) => <li key={i}>{w}</li>)}
            </ul>
          )}
        </div>
      )}

      {stage === 'apply' && result && (
        <div className="mt-3 rounded-md border border-radar-accent/40 bg-radar-accent/5 p-3 text-[12px] text-radar-text" data-testid="inventory-import-result">
          <p className="inline-flex items-center gap-2"><FileSearch className="h-3 w-3" />Imported {result.componentCount} components.</p>
          <p className="mt-1">{result.correlationCount} correlation(s) computed against the public dataset.</p>
        </div>
      )}

      {error && (
        <p role="alert" aria-live="polite" className="mt-3 inline-flex items-center gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="inventory-import-error">
          <AlertTriangle className="h-3 w-3" />
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
        >
          {stage === 'apply' ? 'Close' : 'Cancel'}
        </button>
        {stage === 'preview' && (
          <button
            type="button"
            onClick={handleApply}
            disabled={busy || !parsed}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50"
            data-testid="inventory-import-apply"
          >
            <Upload className="h-3.5 w-3.5" />
            {busy ? 'Applying…' : 'Apply inventory'}
          </button>
        )}
      </div>
    </ReportDialogShell>
  );
}
