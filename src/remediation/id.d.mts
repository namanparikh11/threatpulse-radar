/**
 * V6.7 — Deterministic ID helpers type declarations.
 */
export function fnv1a(str: string): number;
export function makeId(namespace: string, key: string): string;
export function makePlanId(key: string): string;
export function makeTaskId(key: string): string;
export function makeEvidenceId(key: string): string;
export function makeEventId(key: string): string;
export function makeMutationId(): string;
export function nowIso(): string;
