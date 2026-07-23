/**
 * V6.6 — Package URL (types).
 */
export const SUPPORTED_TYPES: ReadonlySet<string>;

export interface ParsedPurl {
  purl: string;
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  qualifiers: string | null;
  subpath: string | null;
}

export function parsePurl(input: string): { ok: true; value: ParsedPurl } | { ok: false; reason: string };
export function normalizeEcosystem(input: string): string | null;
export function normalizeIdentity(input: { purl?: string | null; ecosystem?: string | null; namespace?: string | null; name?: string | null; version?: string | null; cpe?: string | null }): any;
export function isValidPurl(input: string): boolean;
