/**
 * V6.5 — TypeScript declarations for the integrity
 * helpers. Mirrors the JS surface.
 */

export function computeIntegrity(report: any): Promise<{ canonicalizationVersion: string; checksum: string }>;
export function computeIntegrityFromHex(report: any, hex: string): { canonicalizationVersion: string; checksum: string };
export function shortChecksum(checksum: string): string;
export { ShaUnavailableError } from './sha256.mjs';
