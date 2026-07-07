/**
 * Severity-derived helpers. Centralized so colors / ordering
 * stay consistent across the table, badges, and charts.
 */
import type { Severity } from '../types/vulnerability';

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

export const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: '#f43f5e',
  High: '#fb923c',
  Medium: '#facc15',
  Low: '#38bdf8',
};

/** Tailwind classes are easier to mix than inline hex sometimes — kept here for badges. */
export const SEVERITY_BADGE: Record<Severity, string> = {
  Critical:
    'bg-radar-critical/15 text-radar-critical border-radar-critical/30',
  High: 'bg-radar-high/15 text-radar-high border-radar-high/30',
  Medium: 'bg-radar-medium/15 text-radar-medium border-radar-medium/30',
  Low: 'bg-radar-low/15 text-radar-low border-radar-low/30',
};

export function severityFromCvss(score: number): Severity {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}
