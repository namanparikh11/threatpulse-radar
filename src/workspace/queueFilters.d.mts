/**
 * V6.4 — TypeScript declarations for the queue filter
 * helpers. Mirrors the JS surface exactly.
 */

export type QueueFilterId =
  | 'all-watched'
  | 'needs-review'
  | 'action-required'
  | 'changed-since-review'
  | 'high-or-urgent'
  | 'resolved'
  | 'archived';

export interface QueueFilter {
  id: QueueFilterId;
  label: string;
}

export const QUEUE_FILTERS: ReadonlyArray<QueueFilter>;
export const DEFAULT_QUEUE_FILTER: QueueFilterId;

export interface MatchesQueueFilterArgs {
  vuln: any;
  entry: any;
  filter: QueueFilterId;
  publicIntelligenceVersion: string | null | undefined;
  currentChangeSignature: string;
  presentInPublic: boolean;
}
export function matchesQueueFilter(args: MatchesQueueFilterArgs): boolean;

export interface MatchesLocalSearchArgs {
  vuln: any;
  entry: any;
  query: string;
}
export function matchesLocalSearch(args: MatchesLocalSearchArgs): boolean;

export interface BuildLocalQueueArgs {
  vulns: any[];
  entriesByCve: Record<string, any>;
  filter: QueueFilterId;
  query: string;
  publicIntelligenceVersion: string | null | undefined;
  computeSignature?: (vuln: any, publicIntelligenceVersion: string | null | undefined) => string;
}
export interface QueueItem {
  vuln: any;
  entry: any;
  changeClass: 'unavailable' | 'no-newer' | 'changed' | 'newly-tracked' | 'no-longer-tracked';
}
export function buildLocalQueue(args: BuildLocalQueueArgs): QueueItem[];
export function compareQueueItems(a: QueueItem, b: QueueItem): number;

export interface BuildCountsArgs {
  vulns: any[];
  entriesByCve: Record<string, any>;
  publicIntelligenceVersion: string | null | undefined;
  computeSignature?: (vuln: any, publicIntelligenceVersion: string | null | undefined) => string;
}
export interface LocalCounts {
  total: number;
  watched: number;
  unreviewed: number;
  actionRequired: number;
  changedSinceReview: number;
  resolved: number;
  archived: number;
}
export function buildCounts(args: BuildCountsArgs): LocalCounts;
