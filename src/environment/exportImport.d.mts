/**
 * V6.6 — Environment export/import (types).
 */
export const ENVIRONMENT_EXPORT_FORMAT: 'threatpulse-local-environment';
export const ENVIRONMENT_EXPORT_SCHEMA: '1.0.0';

export function buildExportPayload(args: { assets: any[]; inventories: any[]; components: any[]; correlationReviews: any[]; applicationVersion: string; options?: { exportedAt?: string } }): any;
export function stampExportChecksum(payload: any): Promise<any>;
export function validateImportPayload(input: any): { ok: true; value: any; count: { assets: number; inventories: number; components: number; reviews: number } } | { ok: false; reason: string };
export function verifyImportChecksum(payload: any): Promise<{ ok: boolean; computed: string; expected: string; reason?: string }>;
export function applyImportPayload(adapter: any, payload: any, mode: 'merge' | 'replace'): Promise<{ ok: true; counts: any } | { ok: false; reason: string }>;
