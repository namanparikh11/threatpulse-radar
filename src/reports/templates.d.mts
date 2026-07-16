/**
 * V6.5 — TypeScript declarations for the templates
 * module. Mirrors the JS surface.
 */

export function renderLimitations(snapshot: any, extra?: string[]): string[];
export function renderProvenance(snapshot: any): any[];
export function buildSections(reportType: string, snapshot: any, options: any): any[];
export function buildReport(args: {
  reportId: string;
  reportType: string;
  title: string;
  generatedAt: string;
  applicationVersion: string;
  snapshot: any;
  mode: string;
  includePrivateNotes: boolean;
  includeLocalTags: boolean;
}): any;

export { describeField } from './redaction.mjs';
