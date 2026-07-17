/**
 * V6.7 — Dispatcher type declarations.
 */
export const REASONS: {
  readonly CANCELLED: 'cancelled';
  readonly WORKER_UNAVAILABLE: 'worker-unavailable';
  readonly INVALID_MESSAGE: 'invalid-message';
  readonly UNKNOWN: 'unknown';
  readonly TOO_LARGE: 'file-too-large';
};
export const MAX_FILE_BYTES: number;

export interface FingerprintArgs {
  name?: string;
  mimeType?: string;
  sizeBytes?: number;
  lastModified?: number | null;
  buffer: Uint8Array;
  onProgress?: (p: { processed: number; total: number }) => void;
}
export interface VerifyArgs {
  name?: string;
  mimeType?: string;
  sizeBytes?: number;
  lastModified?: number | null;
  buffer: Uint8Array;
  expected: string;
  onProgress?: (p: { processed: number; total: number }) => void;
}
export interface FingerprintResult {
  fileName: string;
  sizeBytes: number;
  mimeType: string;
  lastModified: number | null;
  checksum: string;
}
export interface JobHandle<T> {
  cancel(): void;
  onProgress(cb: (p: { processed: number; total: number }) => void): void;
  result(): Promise<{ ok: boolean; reason?: string; fingerprint?: FingerprintResult; verifyOutcome?: string }>;
}
export function startFingerprintJob(args: FingerprintArgs): { handle: JobHandle<FingerprintResult> };
export function startVerifyJob(args: VerifyArgs): { handle: JobHandle<FingerprintResult> };
