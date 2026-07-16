/**
 * V6.5 — TypeScript declarations for the public
 * SHA-256 entry. Mirrors the JS surface.
 */

export const ACTIVE_IMPL: 'browser' | 'node';

export class ShaUnavailableError extends Error {
  readonly name: 'ShaUnavailableError';
}

export function isAvailable(): Promise<boolean>;
export function digest(bytes: Uint8Array | ArrayBuffer | string): Promise<string>;
export function digestString(s: string): Promise<string>;
export function digestPrefixed(s: string): Promise<string>;
