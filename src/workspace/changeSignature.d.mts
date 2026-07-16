/**
 * V6.4 — TypeScript declarations for the change
 * signature helpers. Mirrors the JS surface.
 */

export function computeChangeSignature(
  vuln: unknown,
  publicIntelligenceVersion: string | null | undefined,
  publicProjectionSchemaVersion?: string | null
): Promise<string>;

export function computeChangeSignatureSync(
  vuln: unknown,
  publicIntelligenceVersion: string | null | undefined,
  publicProjectionSchemaVersion?: string | null
): string;

export function publicVersionsEqual(a: unknown, b: unknown): boolean;

export type ChangeLabel =
  | 'unavailable'
  | 'no-newer'
  | 'changed'
  | 'newly-tracked'
  | 'no-longer-tracked';

export function classifyChange(args: {
  currentVersion: string | null | undefined;
  currentProjectionSchemaVersion?: string | null;
  currentSignature: string;
  record:
    | {
        lastSeenPublicIntelligenceVersion?: string | null;
        lastSeenChangeSignature?: string | null;
        lastSeenPublicProjectionSchemaVersion?: string | null;
      }
    | null
    | undefined;
  presentInPublic?: boolean;
}): ChangeLabel;
