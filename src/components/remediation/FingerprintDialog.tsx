/**
 * V6.7 — File-fingerprint dialog.
 *
 * Lets the operator pick a local file and produces
 * a fingerprint record (name + size + MIME + lastModified
 * + SHA-256). The file bytes never leave the device.
 * The dialog surfaces cancellation and progress so
 * 25 MiB files do not freeze the interface.
 */
import { useEffect, useRef, useState } from 'react';
import { startFingerprintJob, startVerifyJob, REASONS, MAX_FILE_BYTES } from '../../remediation/workers/dispatcher.mjs';

interface FingerprintDialogProps {
  open: boolean;
  initialFingerprint?: any | null;
  onClose(): void;
  onResult(fingerprint: any): void;
}

export function FingerprintDialog({ open, initialFingerprint, onClose, onResult }: FingerprintDialogProps) {
  const [name, setName] = useState('');
  const [sizeBytes, setSizeBytes] = useState<number>(0);
  const [mimeType, setMimeType] = useState('');
  const [lastModified, setLastModified] = useState<number | null>(null);
  const [buffer, setBuffer] = useState<Uint8Array | null>(null);
  const [progress, setProgress] = useState<{ processed: number; total: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [result, setResult] = useState<any | null>(initialFingerprint || null);
  const [error, setError] = useState<string | null>(null);
  const [verifyOutcome, setVerifyOutcome] = useState<string | null>(null);
  const handleRef = useRef<any>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setName('');
    setSizeBytes(0);
    setMimeType('');
    setLastModified(null);
    setBuffer(null);
    setProgress(null);
    setBusy(false);
    setCancelled(false);
    setResult(initialFingerprint || null);
    setError(null);
    setVerifyOutcome(null);
    handleRef.current = null;
  }, [open, initialFingerprint]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const onPick = async (file: File | null) => {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError('file-too-large');
      return;
    }
    setName(file.name);
    setSizeBytes(file.size);
    setMimeType(file.type || '');
    setLastModified(typeof file.lastModified === 'number' ? file.lastModified : null);
    setResult(null);
    setVerifyOutcome(null);
    setError(null);
    setProgress(null);
    setCancelled(false);
    const ab = await file.arrayBuffer();
    setBuffer(new Uint8Array(ab));
  };

  const start = () => {
    if (!buffer) return;
    setBusy(true);
    setError(null);
    setProgress({ processed: 0, total: buffer.length });
    const { handle } = startFingerprintJob({
      name,
      mimeType,
      sizeBytes,
      lastModified,
      buffer,
      onProgress: (p) => setProgress(p),
    });
    handleRef.current = handle;
    handle.result().then((r) => {
      setBusy(false);
      if (!r.ok) {
        if (r.reason === REASONS.CANCELLED) {
          setCancelled(true);
          setProgress(null);
          return;
        }
        setError(r.reason || 'fingerprint-failed');
        setProgress(null);
        return;
      }
      setResult(r.fingerprint);
      setProgress(null);
    });
  };

  const cancel = () => {
    if (handleRef.current) handleRef.current.cancel();
    setCancelled(true);
    setBusy(false);
  };

  const verify = () => {
    if (!buffer || !result) return;
    setBusy(true);
    setError(null);
    setVerifyOutcome(null);
    const { handle } = startVerifyJob({
      name, mimeType, sizeBytes, lastModified, buffer, expected: result.checksum,
    });
    handle.result().then((r) => {
      setBusy(false);
      if (!r.ok) {
        setError(r.reason || 'verify-failed');
        return;
      }
      setVerifyOutcome(r.verifyOutcome || 'unknown');
    });
  };

  const accept = () => {
    if (!result) return;
    onResult(result);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Fingerprint evidence file"
      className="fixed inset-0 z-40 flex items-center justify-center bg-radar-bg/70 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="panel max-w-md w-full p-4 space-y-3 text-[12px]" role="document">
        <h2 className="text-sm font-semibold text-radar-text">Fingerprint local file</h2>
        <p className="text-[11px] text-radar-muted">
          The file stays on this device. The dialog only records the file name, size, MIME type, lastModified timestamp, and SHA-256 checksum. No file bytes are uploaded or stored.
        </p>
        <label className="block">
          <span className="text-[10px] text-radar-muted">Local file (max {(MAX_FILE_BYTES / 1024 / 1024).toFixed(0)} MiB)</span>
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => onPick(e.target.files && e.target.files[0])}
            disabled={busy}
            className="focus-ring mt-1 block w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-text"
            aria-label="Choose local file"
            data-testid="fingerprint-dialog-file"
          />
        </label>
        {name && (
          <div className="rounded-md border border-radar-border bg-radar-panel2/40 p-2 text-[11px] text-radar-text">
            <p className="font-mono break-all" data-testid="fingerprint-dialog-name">{name}</p>
            <p className="text-radar-dim">{sizeBytes} bytes · {mimeType || 'unknown mime'} · {lastModified ? new Date(lastModified).toISOString() : 'no lastModified'}</p>
          </div>
        )}
        {progress && (
          <div className="text-[11px] text-radar-muted" aria-live="polite" data-testid="fingerprint-dialog-progress">
            Hashing {progress.processed} / {progress.total} bytes…
            <div className="mt-1 h-1.5 w-full rounded bg-radar-panel2">
              <div className="h-1.5 rounded bg-radar-accent" style={{ width: `${progress.total > 0 ? Math.floor((progress.processed / progress.total) * 100) : 0}%` }} />
            </div>
          </div>
        )}
        {cancelled && !busy && !result && (
          <p className="rounded-md border border-radar-border bg-radar-panel2/40 px-2 py-1 text-[11px] text-radar-muted" role="status" aria-live="polite" data-testid="fingerprint-dialog-cancelled">
            Cancelled. Pick a file and try again.
          </p>
        )}
        {result && (
          <div className="rounded-md border border-radar-accent/40 bg-radar-accent/5 p-2 text-[11px] text-radar-text" data-testid="fingerprint-dialog-result">
            <p className="font-mono break-all">{result.checksum}</p>
            <p className="text-radar-dim">{result.fileName} · {result.sizeBytes} bytes</p>
          </div>
        )}
        {verifyOutcome && (
          <p className="rounded-md border border-radar-border bg-radar-panel2/40 px-2 py-1 text-[11px] text-radar-text" role="status" aria-live="polite" data-testid="fingerprint-dialog-verify">
            Verification: {verifyOutcome === 'matches' ? 'matches recorded fingerprint' : verifyOutcome === 'differs' ? 'does NOT match recorded fingerprint' : verifyOutcome}
          </p>
        )}
        {error && (
          <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="fingerprint-dialog-error">
            {error === 'file-too-large' ? `File is larger than ${(MAX_FILE_BYTES / 1024 / 1024).toFixed(0)} MiB.` : error}
          </p>
        )}
        <p className="text-[10px] text-radar-dim">
          A matching checksum is a local byte-identity check. It does not prove authorship, identity, timestamp authority, or legal authenticity.
        </p>
        <div className="flex items-center justify-end gap-2 border-t border-radar-border/40 pt-3">
          {busy ? (
            <button type="button" onClick={cancel} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn" data-testid="fingerprint-dialog-cancel">
              Cancel
            </button>
          ) : (
            <>
              <button type="button" onClick={onClose} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text">
                Close
              </button>
              {buffer && !result && (
                <button type="button" onClick={start} disabled={!buffer} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50" data-testid="fingerprint-dialog-start">
                  Fingerprint
                </button>
              )}
              {result && buffer && (
                <button type="button" onClick={verify} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text" data-testid="fingerprint-dialog-verify-btn">
                  Verify against new file
                </button>
              )}
              {result && (
                <button type="button" onClick={accept} className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110" data-testid="fingerprint-dialog-accept">
                  Use this fingerprint
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
