/**
 * V6.1 — One per-CVE change row inside the What Changed panel.
 *
 * Clicking the row opens the existing DetailDrawer with
 * the row's CVE selected. The drawer automatically carries
 * the per-CVE change field (added in the V6.1 OSV drawer
 * section).
 */

import { ArrowRight, ExternalLink } from 'lucide-react';
import type { ChangeItem } from '../types/change';

interface ChangeItemRowProps {
  item: ChangeItem;
  onOpen: (cveId: string) => void;
}

const CLASS_LABEL: Record<string, string> = {
  'cve-newly-tracked': 'Newly tracked',
  'cve-no-longer-tracked': 'No longer tracked',
  'kev-newly-present': 'KEV newly present',
  'kev-no-longer-present': 'KEV no longer present',
  'severity-class-changed': 'Severity class changed',
  'cvss-source-or-version-changed': 'CVSS source or version changed',
  'epss-materially-increased': 'EPSS materially increased',
  'epss-materially-decreased': 'EPSS materially decreased',
  'ssvc-state-changed': 'SSVC state changed',
  'ssvc-data-newly-available': 'SSVC data newly available',
  'github-advisory-newly-available': 'GitHub Advisory newly available',
  'github-advisory-no-longer-available': 'GitHub Advisory no longer available',
  'first-patched-newly-available': 'First patched newly available',
  'first-patched-no-longer-available': 'First patched no longer available',
  'osv-record-newly-correlated': 'OSV record newly correlated',
  'osv-record-removed': 'OSV record removed',
  'osv-record-set-changed': 'OSV record set changed',
  'affected-package-or-range-changed': 'Affected package or range changed',
  'withdrawn': 'Withdrawn',
};

function describeTransition(item: ChangeItem): string | null {
  const parts: string[] = [];
  if (item.severityFrom && item.severityTo && item.severityFrom !== item.severityTo) {
    parts.push(`Severity: ${item.severityFrom} → ${item.severityTo}`);
  }
  if (
    typeof item.epssFrom === 'number' &&
    typeof item.epssTo === 'number' &&
    item.epssFrom !== item.epssTo
  ) {
    const pct = Math.abs(item.epssTo - item.epssFrom) * 100;
    parts.push(`EPSS: ${(item.epssFrom * 100).toFixed(0)}% → ${(item.epssTo * 100).toFixed(0)}% (${pct >= 10 ? '≥10pp' : '<' + pct.toFixed(0) + 'pp'})`);
  }
  if (
    typeof item.kevFrom === 'boolean' &&
    typeof item.kevTo === 'boolean' &&
    item.kevFrom !== item.kevTo
  ) {
    parts.push(`KEV: ${item.kevFrom ? 'present' : 'absent'} → ${item.kevTo ? 'present' : 'absent'}`);
  }
  if (item.ssvcFrom && item.ssvcTo && item.ssvcFrom !== item.ssvcTo) {
    parts.push(`SSVC: ${item.ssvcFrom} → ${item.ssvcTo}`);
  }
  if (item.githubAdvisoryFrom !== item.githubAdvisoryTo) {
    parts.push(`GitHub Advisory: ${item.githubAdvisoryFrom || 'none'} → ${item.githubAdvisoryTo || 'none'}`);
  }
  return parts.length > 0 ? parts.join('; ') : null;
}

export default function ChangeItemRow({ item, onOpen }: ChangeItemRowProps) {
  const transition = describeTransition(item);
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(item.cveId)}
        className="focus-ring group flex w-full items-center justify-between gap-3 px-3 py-2 text-left transition hover:bg-radar-panel2/60"
        data-testid="change-item-row"
        data-cve-id={item.cveId}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-xs text-radar-accent">{item.cveId}</span>
            <ArrowRight className="h-3 w-3 text-radar-dim" />
            <span className="text-xs text-radar-text">
              {item.classifications.slice(0, 3).map((c) => CLASS_LABEL[c] || c).join(', ')}
              {item.classifications.length > 3 ? ` +${item.classifications.length - 3} more` : ''}
            </span>
          </div>
          {transition ? (
            <div className="mt-0.5 text-[11px] text-radar-dim">{transition}</div>
          ) : null}
        </div>
        <ExternalLink className="h-3.5 w-3.5 shrink-0 text-radar-dim opacity-0 transition group-hover:opacity-100" />
      </button>
    </li>
  );
}
