/**
 * V6.5 — Report verification (types).
 */
export type VerifyStatus =
  | 'valid'
  | 'valid-shape'
  | 'unsupported-schema'
  | 'invalid-format'
  | 'too-large'
  | 'corrupt'
  | 'incomplete'
  | 'integrity-failed'
  | 'integrity-unavailable';

export interface VerifyResult {
  ok: boolean;
  status: VerifyStatus;
  report: any | null;
}

export function verifyJson(jsonString: string): Promise<VerifyResult>;
export function verifyReport(report: any): Promise<VerifyResult>;
export function verifyShape(report: any): VerifyResult;
export const verify: (jsonString: string) => Promise<VerifyResult>;
