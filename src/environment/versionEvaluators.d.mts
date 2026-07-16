/**
 * V6.6 — Version evaluators (types).
 */
export interface VersionEvalResult {
  state: 'affected-range-match' | 'exact-version-match' | 'version-not-evaluable' | 'no-supported-match';
  explanation: string;
  evaluatedRange: string | null;
}

export const VERSION_EVALUATORS: Record<string, (version: string, rangeText: string) => VersionEvalResult>;
export const EVALUATOR_TEST_VECTORS: readonly any[];

export function evaluateVersion(ecosystem: string | null, version: string, rangeText: string): VersionEvalResult;
