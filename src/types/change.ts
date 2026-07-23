/**
 * V6.1 — Change intelligence types.
 *
 * The change intelligence surface is panel-local. The
 * browser receives per-category results through the
 * `view=changes` query mode on the dataset function.
 */

export type ChangeClassification =
  | 'cve-newly-tracked'
  | 'cve-no-longer-tracked'
  | 'kev-newly-present'
  | 'kev-no-longer-present'
  | 'severity-class-changed'
  | 'cvss-source-or-version-changed'
  | 'epss-materially-increased'
  | 'epss-materially-decreased'
  | 'ssvc-state-changed'
  | 'ssvc-data-newly-available'
  | 'github-advisory-newly-available'
  | 'github-advisory-no-longer-available'
  | 'first-patched-newly-available'
  | 'first-patched-no-longer-available'
  | 'osv-record-newly-correlated'
  | 'osv-record-removed'
  | 'osv-record-set-changed'
  | 'affected-package-or-range-changed'
  | 'withdrawn';

export type ChangePanelCategory =
  | 'newly-tracked'
  | 'no-longer-tracked'
  | 'fact-newly-available'
  | 'fact-changed'
  | 'fact-no-longer-present'
  | 'provider-status-changed';

export type ChangeItem = {
  cveId: string;
  classifications: ChangeClassification[];
  publicIntelligenceVersion: string;
  severityFrom?: string | null;
  severityTo?: string | null;
  epssFrom?: number | null;
  epssTo?: number | null;
  kevFrom?: boolean | null;
  kevTo?: boolean | null;
  ssvcFrom?: string | null;
  ssvcTo?: string | null;
  githubAdvisoryFrom?: string | null;
  githubAdvisoryTo?: string | null;
  osvFrom?: { recordIds: string[] } | null;
  osvTo?: { recordIds: string[] } | null;
};

export type ChangeSummary = {
  newlyTracked: number;
  noLongerTracked: number;
  factNewlyAvailable: number;
  factChanged: number;
  factNoLongerPresent: number;
  providerStatusChanged: number;
  epssMateriallyIncreased: number;
  epssMateriallyDecreased: number;
};

export type ChangeTag = {
  classifications: ChangeClassification[];
  since: string;
  baseVersion: string;
};
