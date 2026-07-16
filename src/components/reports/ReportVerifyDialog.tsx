/**
 * V6.5 — Report verification + comparison dialog.
 *
 * Lets the operator:
 *   - load a single JSON report and verify it
 *     (parse + schema + size + integrity recompute)
 *   - load two JSON reports and compare them
 *     (verify both, then diff metadata / CVEs /
 *     provider facts / local fields / provenance /
 *     limitations)
 *
 * Files are read with `FileReader` and parsed in
 * the browser. The dialog NEVER writes the file
 * content to disk, the URL, the history, or the
 * console. Files are not stored; only the
 * verification + comparison results are surfaced.
 */

import { useCallback, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileWarning } from 'lucide-react';
import { verifyJson, type VerifyResult } from '../../reports/verify.mjs';
import { compareReports, type DiffResult } from '../../reports/compare.mjs';
import { REPORT_LIMITS } from '../../reports/schema.mjs';
import ReportDialogShell from './ReportDialogShell';

export interface ReportVerifyDialogProps {
  /** When 'verify' only verify flow is exposed.
   *  When 'compare' only compare flow is exposed. */
  mode: 'verify' | 'compare';
  onClose: () => void;
}

const STATUS_LABEL: Record<string, string> = {
  'valid': 'Valid',
  'valid-shape': 'Valid shape (integrity pending)',
  'unsupported-schema': 'Unsupported schema version',
  'invalid-format': 'Invalid format',
  'too-large': 'Payload too large',
  'corrupt': 'Corrupt report',
  'incomplete': 'Incomplete report',
  'integrity-failed': 'Integrity check failed',
  'integrity-unavailable': 'SHA-256 unavailable in this runtime',
};

function statusTone(status: string): string {
  if (status === 'valid') return 'border-radar-accent/40 bg-radar-accent/10 text-radar-accent';
  if (status === 'valid-shape') return 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent';
  return 'border-radar-warn/40 bg-radar-warn/5 text-radar-warn';
}

async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(typeof fr.result === 'string' ? fr.result : '');
    fr.onerror = () => reject(fr.error || new Error('read-failed'));
    fr.readAsText(file);
  });
}

export default function ReportVerifyDialog({ mode, onClose }: ReportVerifyDialogProps) {
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [compareResult, setCompareResult] = useState<DiffResult | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputARef = useRef<HTMLInputElement | null>(null);
  const fileInputBRef = useRef<HTMLInputElement | null>(null);

  const onPickVerify = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    setVerifyResult(null);
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > REPORT_LIMITS.MAX_BYTES) {
      setError(`File is larger than ${REPORT_LIMITS.MAX_BYTES} bytes.`);
      return;
    }
    setBusy(true);
    try {
      const text = await readFileAsText(f);
      const out = await verifyJson(text);
      setVerifyResult(out);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'verify-failed');
    } finally {
      setBusy(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }, []);

  const onPickCompare = useCallback(async () => {
    setError(null);
    setCompareResult(null);
    const a = fileInputARef.current?.files && fileInputARef.current.files[0];
    const b = fileInputBRef.current?.files && fileInputBRef.current.files[0];
    if (!a || !b) {
      setError('Choose two JSON report files to compare.');
      return;
    }
    if (a.size > REPORT_LIMITS.MAX_BYTES || b.size > REPORT_LIMITS.MAX_BYTES) {
      setError(`One of the files is larger than ${REPORT_LIMITS.MAX_BYTES} bytes.`);
      return;
    }
    setBusy(true);
    try {
      const ta = await readFileAsText(a);
      const tb = await readFileAsText(b);
      const ra = await verifyJson(ta);
      const rb = await verifyJson(tb);
      if (!ra.ok) {
        setError(`Left report: ${STATUS_LABEL[ra.status] || ra.status}`);
        return;
      }
      if (!rb.ok) {
        setError(`Right report: ${STATUS_LABEL[rb.status] || rb.status}`);
        return;
      }
      const diff = await compareReports(ra.report, rb.report);
      setCompareResult(diff);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'compare-failed');
    } finally {
      setBusy(false);
    }
  }, []);

  return (
    <ReportDialogShell title={mode === 'verify' ? 'Verify report' : 'Compare reports'} onClose={onClose}>
      {mode === 'verify' ? (
        <div className="space-y-3">
          <p className="text-[11px] text-radar-muted">
            Choose a <code>.json</code> report bundle. The file is parsed in the browser; nothing is uploaded.
          </p>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json,.json"
            onChange={onPickVerify}
            className="focus-ring block w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text file:mr-2 file:rounded-md file:border-0 file:bg-radar-panel file:px-2 file:py-1 file:text-radar-text"
            aria-label="Choose a JSON report to verify"
            data-testid="report-verify-file"
          />
          {busy && <p className="text-[11px] text-radar-muted">Verifying…</p>}
          {verifyResult && (
            <div
              className={['inline-flex items-center gap-2 rounded-md border px-2 py-1 text-[12px]', statusTone(verifyResult.status)].join(' ')}
              role="status"
              aria-live="polite"
              data-testid="report-verify-status"
            >
              {verifyResult.ok ? <CheckCircle2 className="h-3 w-3" /> : <FileWarning className="h-3 w-3" />}
              {STATUS_LABEL[verifyResult.status] || verifyResult.status}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-[11px] text-radar-muted">
            Choose two <code>.json</code> report bundles. Both must verify before the diff runs.
          </p>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <label className="block">
              <span className="text-[10px] text-radar-muted">Left (older)</span>
              <input
                ref={fileInputARef}
                type="file"
                accept="application/json,.json"
                className="focus-ring mt-1 block w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text file:mr-2 file:rounded-md file:border-0 file:bg-radar-panel file:px-2 file:py-1 file:text-radar-text"
                aria-label="Older JSON report"
                data-testid="report-compare-file-a"
              />
            </label>
            <label className="block">
              <span className="text-[10px] text-radar-muted">Right (newer)</span>
              <input
                ref={fileInputBRef}
                type="file"
                accept="application/json,.json"
                className="focus-ring mt-1 block w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text file:mr-2 file:rounded-md file:border-0 file:bg-radar-panel file:px-2 file:py-1 file:text-radar-text"
                aria-label="Newer JSON report"
                data-testid="report-compare-file-b"
              />
            </label>
          </div>
          <button
            type="button"
            onClick={onPickCompare}
            disabled={busy}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2.5 py-1 text-[11px] text-radar-accent transition hover:border-radar-accent disabled:opacity-50"
            data-testid="report-compare-run"
          >
            {busy ? 'Comparing…' : 'Compare'}
          </button>
          {compareResult && compareResult.ok && (
            <div className="space-y-2 text-[11px] text-radar-text">
              <p>
                <span className="text-radar-muted">Left: </span>
                <span className="font-mono">{compareResult.left?.reportId}</span>
                <span className="text-radar-dim"> · {compareResult.left?.generatedAt}</span>
              </p>
              <p>
                <span className="text-radar-muted">Right: </span>
                <span className="font-mono">{compareResult.right?.reportId}</span>
                <span className="text-radar-dim"> · {compareResult.right?.generatedAt}</span>
              </p>
              <table className="w-full border-collapse text-[11px]">
                <caption className="sr-only">Report diff summary</caption>
                <tbody>
                  <DiffRow label="Metadata changes" value={compareResult.metadata?.changed?.length || 0} />
                  <DiffRow label="Public intel changes" value={compareResult.publicIntelligence?.changed?.length || 0} />
                  <DiffRow label="CVEs added" value={compareResult.cves?.added?.length || 0} />
                  <DiffRow label="CVEs removed" value={compareResult.cves?.removed?.length || 0} />
                  <DiffRow label="Per-CVE provider fact diffs" value={compareResult.providerFacts?.length || 0} />
                  <DiffRow label="Per-CVE local fact diffs" value={compareResult.localFacts?.length || 0} />
                  <DiffRow label="Provenance added / removed" value={`${compareResult.provenance?.added?.length || 0} / ${compareResult.provenance?.removed?.length || 0}`} />
                  <DiffRow label="Limitations added / removed" value={`${compareResult.limitations?.added?.length || 0} / ${compareResult.limitations?.removed?.length || 0}`} />
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {error && (
        <p role="alert" aria-live="polite" className="mt-3 inline-flex items-center gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="report-verify-error">
          <AlertTriangle className="h-3 w-3" />
          {error}
        </p>
      )}
    </ReportDialogShell>
  );
}

function DiffRow({ label, value }: { label: string; value: number | string }) {
  return (
    <tr className="align-top">
      <th scope="row" className="w-1/2 border-b border-radar-border/40 px-2 py-1 text-left text-[10px] font-medium text-radar-muted">{label}</th>
      <td className="border-b border-radar-border/40 px-2 py-1 font-mono text-radar-text">{String(value)}</td>
    </tr>
  );
}
