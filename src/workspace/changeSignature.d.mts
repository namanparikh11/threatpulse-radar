export function computeChangeSignature(
  vuln: unknown,
  publicIntelligenceVersion: string | null | undefined
): string;
export function versionsAreCompatible(a: unknown, b: unknown): boolean;
export type ChangeLabel =
  | 'unavailable'
  | 'no-newer'
  | 'changed'
  | 'newly-tracked'
  | 'no-longer-tracked';
export function classifyChange(args: {
  currentVersion: string;
  currentSignature: string;
  record:
    | {
        lastSeenPublicIntelligenceVersion?: string | null;
        lastSeenChangeSignature?: string | null;
      }
    | null
    | undefined;
  presentInPublic?: boolean;
}): ChangeLabel;
