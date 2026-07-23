/**
 * V6.7 — Remediation hash type declarations.
 */
export class ShaUnavailableError extends Error {
  constructor();
  name: 'ShaUnavailableError';
}

export function isAvailable(): boolean;
export function sha256Hex(str: string): Promise<string>;
export function sha256HexBytes(bytes: Uint8Array | ArrayBuffer): Promise<string>;
export function sha256HexPrefixed(str: string): Promise<string>;
