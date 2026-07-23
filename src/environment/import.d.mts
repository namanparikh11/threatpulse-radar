/**
 * V6.6 — Import (types).
 */
export interface ImportOptions { assetId: string; inventoryId: string }
export interface ParsedImport {
  format: 'cyclonedx-json' | 'spdx-json' | 'threatpulse-inventory-json' | 'csv';
  sourceVersion: string | null;
  components: any[];
  warnings: string[];
  rejected: number;
  sizeBytes: number;
}

export function detectFormat(input: string): { format: any; sourceVersion: string | null; reason?: string };
export function parseImport(input: string, options: ImportOptions): { ok: true; result: ParsedImport } | { ok: false; reason: string };
export function parseCycloneDx(input: string, sourceVersion: string, options: ImportOptions): { ok: true; result: ParsedImport } | { ok: false; reason: string };
export function parseSpdx(input: string, sourceVersion: string, options: ImportOptions): { ok: true; result: ParsedImport } | { ok: false; reason: string };
export function parseInventoryJson(input: string, sourceVersion: string | null, options: ImportOptions): { ok: true; result: ParsedImport } | { ok: false; reason: string };
export function parseCsv(input: string, options: ImportOptions): { ok: true; result: ParsedImport } | { ok: false; reason: string };
