/**
 * V6.5 — TypeScript declarations for the redaction
 * helpers. Mirrors the JS surface.
 */

export function modeHidesNote(mode: string): boolean;
export function modeHidesTags(mode: string): boolean;
export function modeHidesStatus(mode: string): boolean;
export function modeHidesBody(mode: string): boolean;
export function fieldKindOf(path: string): 'provider-fact' | 'threatpulse-derived' | 'user-authored' | 'system-metadata' | 'unavailable-or-uncertain';
export function describeField(path: string): string;
