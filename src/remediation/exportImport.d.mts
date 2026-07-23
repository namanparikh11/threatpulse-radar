/**
 * V6.7 — Remediation export/import type declarations.
 */
export const REMEDIATION_BUNDLE_FORMAT: 'threatpulse-local-remediation';
export const REMEDIATION_BUNDLE_VERSION: '1.0.0';
export const REMEDIATION_BUNDLE_MAX_BYTES: number;
export const REMEDIATION_BUNDLE_KIND_PLAN: 'plan';
export const REMEDIATION_BUNDLE_KIND_FULL: 'full';

export function validateImportPayload(json: string): Promise<{ ok: true; value: any } | { ok: false; reason: string }>;
export function buildBundle(plan: any, tasks: any[], evidence: any[], events: any[], options?: { applicationVersion?: string }): Promise<any>;
export function buildFullBundle(plans: any[], tasks: any[], evidence: any[], ledger: any[], options?: { applicationVersion?: string }): Promise<any>;
export function verifyBundleChecksum(parsed: any): Promise<{ ok: boolean; reason?: string }>;
export function dryRunImport(parsed: any, adapter: any): Promise<{ ok: true; decisions: any } | { ok: false; reason: string; decisions?: any }>;
export function applyImport(parsed: any, adapter: any, mode: 'merge' | 'replace'): Promise<{ ok: true; decisions: any } | { ok: false; reason: string; decisions?: any }>;
