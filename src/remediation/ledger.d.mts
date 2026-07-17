/**
 * V6.7 — Ledger type declarations.
 */
export function computeEventHash(event: any): Promise<string>;
export function makeGenesisEvent(args: {
  planId: string;
  eventId: string;
  eventType: string;
  occurredAt: string;
  actorLabel: string;
  summary: string;
  targetIds?: { [key: string]: string };
}): any;
export function makeFollowupEvent(args: {
  planId: string;
  eventId: string;
  sequence: number;
  eventType: string;
  occurredAt: string;
  actorLabel: string;
  summary: string;
  targetIds?: { [key: string]: string };
  previousEventHash: string | null;
}): any;
export function verifyChain(events: any[]): Promise<{ ok: boolean; eventCount?: number; reason?: string; index?: number; expected?: any; actual?: any }>;
