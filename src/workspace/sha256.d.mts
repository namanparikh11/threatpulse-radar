/**
 * V6.4 — TypeScript declarations for the SHA-256
 * helpers. Mirrors the JS surface.
 */

export function sha256HexSync(input: string): string;
export function sha256HexPrefixedSync(input: string): string;
export function isWebCryptoAvailable(): boolean;
export function isNodeCryptoAvailable(): boolean;
export function sha256Hex(input: string): Promise<string>;
export function sha256HexAsync(input: string): Promise<string>;

export class ShaUnavailableError extends Error {
  readonly name: 'ShaUnavailableError';
}
