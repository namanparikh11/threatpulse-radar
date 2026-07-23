/**
 * V6.7 — Lifecycle type declarations.
 */
import type { ValidationResult } from './schema.mjs';

export function isSupportedTransition(from: string, to: string): boolean;
export function checkTransition(from: string, to: string): ValidationResult;
export function isTerminalStatus(status: string): boolean;
export function isActiveStatus(status: string): boolean;
export function allowedTransitionsFrom(from: string): string[];
export function actionableTransitionsFrom(from: string): string[];

export const LIFECYCLE_REASONS: {
  readonly UNSUPPORTED: 'unsupported-status-transition';
  readonly INVALID_STATUS: 'invalid-status';
};
