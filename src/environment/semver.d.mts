/**
 * V6.6 — Semver (types).
 */
export interface Semver {
  major: number;
  minor: number;
  patch: number;
  preRelease: string | null;
  build: string | null;
  raw: string;
}

export function parseSemver(input: string): Semver | null;
export function compareSemver(a: Semver | null, b: Semver | null): -1 | 0 | 1;
export function semverInRange(version: string | Semver | null, lo: Semver | null, hi: Semver | null): boolean;
export const SEMVER_TEST_VECTORS: readonly any[];
