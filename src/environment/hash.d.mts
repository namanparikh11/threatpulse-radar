/**
 * V6.6 — Inventory hash (types).
 */
export function sha256Hex(str: string): Promise<string>;
export function computeInventoryChecksum(components: any[]): Promise<string>;
export function verifyInventoryChecksum(components: any[], expected: string): Promise<boolean>;
