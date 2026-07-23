/**
 * V6.1 — Deterministic change intelligence.
 *
 * The change-intelligence step compares the current
 * successful compatible public snapshot with the previous
 * successful compatible public snapshot and produces a
 * per-CVE classification set + an aggregate summary.
 *
 * Comparability gates:
 *   A classification axis is computed only when both
 *   snapshots report the corresponding provider as
 *   comparable. Otherwise the axis is suppressed (NOT
 *   synthesized as "no change"). The manifest carries
 *   `comparableAxes` and `suppressedAxes` arrays; the
 *   per-CVE item's `suppressedAxes` array is empty when
 *   all axes are comparable.
 *
 * Precedence rules:
 *   - When a CVE enters the tracked universe, the only
 *     classification emitted is `cve-newly-tracked`. No
 *     per-axis classifications are emitted (the CVE has
 *     no `prev` record to compare against).
 *   - When a CVE leaves the tracked universe, the only
 *     classification emitted is `cve-no-longer-tracked`.
 *     No `fact-no-longer-present` or `fact-changed`
 *     classes are emitted.
 *   - All other classifications may co-occur on the same
 *     CVE (the `classifications` array is a set).
 *
 * Panel-level category aggregation:
 *   - Newly tracked (cve-newly-tracked)
 *   - No longer tracked (cve-no-longer-tracked)
 *   - Fact newly available (kev-newly-present, epss-data-newly-available,
 *                          ssvc-data-newly-available,
 *                          github-advisory-newly-available,
 *                          first-patched-newly-available,
 *                          osv-record-newly-correlated)
 *   - Fact changed (severity-class-changed,
 *                  cvss-source-or-version-changed,
 *                  epss-materially-increased,
 *                  epss-materially-decreased,
 *                  ssvc-state-changed,
 *                  osv-record-set-changed,
 *                  affected-package-or-range-changed)
 *   - Fact no longer present (kev-no-longer-present,
 *                            github-advisory-no-longer-available,
 *                            first-patched-no-longer-available,
 *                            osv-record-removed)
 *   - Provider status changed (summary-level; not per-CVE)
 *
 * EPSS threshold:
 *   0.10 absolute (the documented product rule). Delta
 *   >= 0.10 in either direction triggers a separate
 *   increased/decreased classification. Smaller changes
 *   are not classified.
 *
 * Determinism:
 *   The classification predicates are pure functions of
 *   (prev, current). Items are sorted by (categoryOrder,
 *   classificationOrder, cveId). Identical input always
 *   produces identical output.
 *
 * No incomplete-run change claims:
 *   When at least one provider axis is `comparable: true`
 *   in the CURRENT snapshot (i.e. CISA KEV was reachable),
 *   classifications may be emitted. When NO axis is
 *   comparable (CISA KEV gating failed), the change items
 *   array is empty and the `partial: true` flag is set on
 *   the manifest. Never fabricate a change from a failed
 *   run.
 */

export const EPSS_MATERIAL_CHANGE_THRESHOLD = 0.10;

/**
 * All classification identifiers, in the order they
 * appear in the per-CVE `classifications` array. The
 * order is stable across publications and is the
 * secondary sort key for `items[]`.
 */
export const CLASSIFICATION_ORDER = [
  'cve-newly-tracked',
  'cve-no-longer-tracked',
  'kev-newly-present',
  'kev-no-longer-present',
  'severity-class-changed',
  'cvss-source-or-version-changed',
  'epss-materially-increased',
  'epss-materially-decreased',
  'ssvc-state-changed',
  'ssvc-data-newly-available',
  'github-advisory-newly-available',
  'github-advisory-no-longer-available',
  'first-patched-newly-available',
  'first-patched-no-longer-available',
  'osv-record-newly-correlated',
  'osv-record-removed',
  'osv-record-set-changed',
  'affected-package-or-range-changed',
  'withdrawn',
];

export const CLASSIFICATION_SET = new Set(CLASSIFICATION_ORDER);

const CLASSIFICATION_INDEX = {};
for (let i = 0; i < CLASSIFICATION_ORDER.length; i++) {
  CLASSIFICATION_INDEX[CLASSIFICATION_ORDER[i]] = i;
}

/**
 * Panel-level category aggregation. The order is the
 * order of the panel chips.
 */
export const PANEL_CATEGORIES = [
  'newly-tracked',
  'no-longer-tracked',
  'fact-newly-available',
  'fact-changed',
  'fact-no-longer-present',
  'provider-status-changed',
];

/**
 * Map a per-CVE classification to a panel category.
 * Returns `null` for classifications that are summary-level
 * only (e.g. `provider-status-changed`).
 */
export function classificationToCategory(cls) {
  switch (cls) {
    case 'cve-newly-tracked': return 'newly-tracked';
    case 'cve-no-longer-tracked': return 'no-longer-tracked';
    case 'kev-newly-present':
    case 'ssvc-data-newly-available':
    case 'github-advisory-newly-available':
    case 'first-patched-newly-available':
    case 'osv-record-newly-correlated':
      return 'fact-newly-available';
    case 'severity-class-changed':
    case 'cvss-source-or-version-changed':
    case 'epss-materially-increased':
    case 'epss-materially-decreased':
    case 'ssvc-state-changed':
    case 'osv-record-set-changed':
    case 'affected-package-or-range-changed':
      return 'fact-changed';
    case 'kev-no-longer-present':
    case 'github-advisory-no-longer-available':
    case 'first-patched-no-longer-available':
    case 'osv-record-removed':
    case 'withdrawn':
      return 'fact-no-longer-present';
    default:
      return null;
  }
}

const SEVERITY_TIER = { Critical: 4, High: 3, Medium: 2, Low: 1 };

function tierOf(severity) {
  if (typeof severity !== 'string') return 0;
  return SEVERITY_TIER[severity] || 0;
}

/**
 * Determine whether a provider axis is comparable in a
 * snapshot. A snapshot's `providerComparability` block
 * carries `{ comparable: true|false|'partial', asOf: ISO }`
 * per provider.
 */
function isComparable(snapshot, providerKey) {
  if (!snapshot || !snapshot.providerComparability) return false;
  const c = snapshot.providerComparability[providerKey];
  if (!c) return false;
  return c.comparable === true || c.comparable === 'partial';
}

function isFullyComparable(snapshot, providerKey) {
  if (!snapshot || !snapshot.providerComparability) return false;
  const c = snapshot.providerComparability[providerKey];
  return c && c.comparable === true;
}

/**
 * Classify a single CVE given the prev and current
 * snapshot records. Returns the classifications array.
 * Pure.
 */
export function classifyCve(prev, current, prevSnapshot, currentSnapshot) {
  const classes = new Set();

  // Edge case: CVE newly tracked. ONLY this class.
  if ((!prev || prev.tracked === false) && current && current.tracked === true) {
    classes.add('cve-newly-tracked');
    return Array.from(classes);
  }
  // Edge case: CVE no longer tracked. ONLY this class.
  if (prev && prev.tracked === true && (!current || current.tracked === false)) {
    classes.add('cve-no-longer-tracked');
    return Array.from(classes);
  }
  // No prev and no current: skip.
  if (!prev || !current) return [];

  // KEV
  if (isComparable(prevSnapshot, 'cisaKev') && isComparable(currentSnapshot, 'cisaKev')) {
    if (prev.kev && current.kev) {
      if (prev.kev.observation === 'present' && prev.kev.present === false
          && current.kev.observation === 'present' && current.kev.present === true) {
        classes.add('kev-newly-present');
      } else if (prev.kev.observation === 'present' && prev.kev.present === true
          && current.kev.observation === 'present' && current.kev.present === false) {
        classes.add('kev-no-longer-present');
      }
    }
  }

  // Severity
  if (prev.severity && current.severity
      && prev.severity.observation === 'present' && current.severity.observation === 'present') {
    if (tierOf(prev.severity.value) !== tierOf(current.severity.value)) {
      // Only fire when the underlying provider is
      // comparable (NVD).
      if (isComparable(prevSnapshot, 'nvd') && isComparable(currentSnapshot, 'nvd')) {
        classes.add('severity-class-changed');
      }
    }
    if (prev.severity.cvssSource !== current.severity.cvssSource
        || prev.severity.cvssVersion !== current.severity.cvssVersion) {
      if (isComparable(prevSnapshot, 'nvd') && isComparable(currentSnapshot, 'nvd')) {
        classes.add('cvss-source-or-version-changed');
      }
    }
  }

  // EPSS
  if (typeof prev.epssProbability === 'number' && typeof current.epssProbability === 'number') {
    const delta = current.epssProbability - prev.epssProbability;
    // Use a small epsilon to absorb floating-point arithmetic
    // noise (e.g. 0.15 - 0.05 = 0.09999999999999998). The
    // threshold is a documented product rule; the epsilon is
    // for IEEE-754 safety, NOT for lowering the threshold.
    if (Math.abs(delta) >= EPSS_MATERIAL_CHANGE_THRESHOLD - 1e-9) {
      if (isComparable(prevSnapshot, 'firstEpss') && isComparable(currentSnapshot, 'firstEpss')) {
        if (delta > 0) classes.add('epss-materially-increased');
        else if (delta < 0) classes.add('epss-materially-decreased');
      }
    }
  }

  // SSVC
  if (prev.ssvcExploitation && current.ssvcExploitation) {
    if (prev.ssvcExploitation.observation === 'checked-absent' && current.ssvcExploitation.observation === 'present') {
      if (isComparable(prevSnapshot, 'ssvc') && isComparable(currentSnapshot, 'ssvc')) {
        classes.add('ssvc-data-newly-available');
      }
    } else if (prev.ssvcExploitation.observation === 'present' && current.ssvcExploitation.observation === 'present') {
      if (prev.ssvcExploitation.exploitation !== current.ssvcExploitation.exploitation) {
        if (isComparable(prevSnapshot, 'ssvc') && isComparable(currentSnapshot, 'ssvc')) {
          classes.add('ssvc-state-changed');
        }
      }
    }
  }

  // GitHub Advisory
  if (prev.githubAdvisory && current.githubAdvisory) {
    if (prev.githubAdvisory.observation === 'checked-absent' && current.githubAdvisory.observation === 'present') {
      if (isComparable(prevSnapshot, 'githubAdvisory') && isComparable(currentSnapshot, 'githubAdvisory')) {
        classes.add('github-advisory-newly-available');
      }
    } else if (prev.githubAdvisory.observation === 'present' && current.githubAdvisory.observation === 'checked-absent') {
      if (isComparable(prevSnapshot, 'githubAdvisory') && isComparable(currentSnapshot, 'githubAdvisory')) {
        classes.add('github-advisory-no-longer-available');
      }
    }
    if (prev.firstPatchedAvailable === false && current.firstPatchedAvailable === true) {
      if (isComparable(prevSnapshot, 'githubAdvisory') && isComparable(currentSnapshot, 'githubAdvisory')) {
        classes.add('first-patched-newly-available');
      }
    } else if (prev.firstPatchedAvailable === true && current.firstPatchedAvailable === false) {
      if (isComparable(prevSnapshot, 'githubAdvisory') && isComparable(currentSnapshot, 'githubAdvisory')) {
        classes.add('first-patched-no-longer-available');
      }
    }
  }

  // OSV
  if (prev.osv && current.osv) {
    if (prev.osv.observation === 'checked-absent' && current.osv.observation === 'present') {
      if (isComparable(prevSnapshot, 'osv') && isComparable(currentSnapshot, 'osv')) {
        classes.add('osv-record-newly-correlated');
      }
    } else if (prev.osv.observation === 'present' && current.osv.observation === 'checked-absent') {
      if (isComparable(prevSnapshot, 'osv') && isComparable(currentSnapshot, 'osv')) {
        classes.add('osv-record-removed');
      }
    } else if (prev.osv.observation === 'present' && current.osv.observation === 'present') {
      const prevIds = Array.isArray(prev.osv.recordIds) ? prev.osv.recordIds : [];
      const curIds = Array.isArray(current.osv.recordIds) ? current.osv.recordIds : [];
      const prevSet = new Set(prevIds);
      const curSet = new Set(curIds);
      let diff = false;
      for (const id of curSet) if (!prevSet.has(id)) diff = true;
      for (const id of prevSet) if (!curSet.has(id)) diff = true;
      if (diff) {
        if (isComparable(prevSnapshot, 'osv') && isComparable(currentSnapshot, 'osv')) {
          classes.add('osv-record-set-changed');
        }
      }
      if (prev.affectedSignature !== current.affectedSignature) {
        if (isComparable(prevSnapshot, 'osv') && isComparable(currentSnapshot, 'osv')) {
          classes.add('affected-package-or-range-changed');
        }
      }
      if (prev.withdrawn === false && current.withdrawn === true) {
        if (isComparable(prevSnapshot, 'osv') && isComparable(currentSnapshot, 'osv')) {
          classes.add('withdrawn');
        }
      }
    }
  }

  return Array.from(classes);
}

/**
 * Build the per-CVE change-item payload for the changes
 * blob. Returns the full item object including the
 * classifications array, the from/to state, and the
 * publicIntelligenceVersion reference.
 */
export function buildChangeItem(cveId, prev, current, prevSnapshot, currentSnapshot, publicIntelligenceVersion) {
  const classes = classifyCve(prev, current, prevSnapshot, currentSnapshot);
  if (classes.length === 0) return null;
  const item = {
    cveId,
    classifications: classes,
    publicIntelligenceVersion,
  };
  if (prev && current) {
    if (prev.severity && current.severity) {
      if (prev.severity.value !== current.severity.value) {
        item.severityFrom = prev.severity.value;
        item.severityTo = current.severity.value;
      }
    }
    if (typeof prev.epssProbability === 'number' && typeof current.epssProbability === 'number'
        && prev.epssProbability !== current.epssProbability) {
      item.epssFrom = prev.epssProbability;
      item.epssTo = current.epssProbability;
    }
    if (prev.kev && current.kev
        && prev.kev.present !== current.kev.present) {
      item.kevFrom = prev.kev.present;
      item.kevTo = current.kev.present;
    }
    if (prev.ssvcExploitation && current.ssvcExploitation
        && prev.ssvcExploitation.exploitation !== current.ssvcExploitation.exploitation) {
      item.ssvcFrom = prev.ssvcExploitation.exploitation;
      item.ssvcTo = current.ssvcExploitation.exploitation;
    }
    if (prev.githubAdvisory && current.githubAdvisory
        && prev.githubAdvisory.ghsaId !== current.githubAdvisory.ghsaId) {
      item.githubAdvisoryFrom = prev.githubAdvisory.ghsaId;
      item.githubAdvisoryTo = current.githubAdvisory.ghsaId;
    }
    if (prev.osv && current.osv
        && JSON.stringify(prev.osv.recordIds) !== JSON.stringify(current.osv.recordIds)) {
      item.osvFrom = { recordIds: prev.osv.recordIds };
      item.osvTo = { recordIds: current.osv.recordIds };
    }
  }
  return item;
}

/**
 * Build the full change items array and the aggregate
 * summary for a (prev, current) snapshot pair. Pure.
 *
 * The function is also responsible for the no-fabrication
 * rule: when no provider axis is comparable in the
 * CURRENT snapshot (CISA KEV gating failed), the items
 * array is empty and `partial: true` is set.
 */
export function buildChangeIntelligence({ prevSnapshot, currentSnapshot, publicIntelligenceVersion, changeItemsHardCap = 5000 } = {}) {
  if (!currentSnapshot || !currentSnapshot.byCve) {
    return {
      items: [],
      summary: emptySummary(),
      comparableAxes: [],
      suppressedAxes: [],
      partial: true,
      reasons: [{ source: 'cisa-kev', kind: 'no-current-snapshot', message: 'No current snapshot available.' }],
      comparesFreshBase: false,
    };
  }
  // No-fabrication check: at least one axis must be fully
  // comparable in the current snapshot.
  const anyComparable = Object.values(currentSnapshot.providerComparability || {}).some(
    (c) => c && c.comparable === true,
  );
  if (!anyComparable) {
    return {
      items: [],
      summary: emptySummary(),
      comparableAxes: [],
      suppressedAxes: Object.entries(currentSnapshot.providerComparability || {}).map(
        ([axis, c]) => ({ axis, reason: c && c.reason ? c.reason : 'unavailable' }),
      ),
      partial: true,
      reasons: [{ source: 'cisa-kev', kind: 'no-comparable-axis', message: 'No provider axis is comparable in the current snapshot.' }],
      comparesFreshBase: !!prevSnapshot,
    };
  }

  // Build per-CVE items.
  const allCveIds = new Set();
  if (prevSnapshot && prevSnapshot.byCve) for (const id of Object.keys(prevSnapshot.byCve)) allCveIds.add(id);
  for (const id of Object.keys(currentSnapshot.byCve)) allCveIds.add(id);
  const sortedCveIds = Array.from(allCveIds).sort();

  const items = [];
  for (const cveId of sortedCveIds) {
    const prev = prevSnapshot && prevSnapshot.byCve ? prevSnapshot.byCve[cveId] : null;
    const current = currentSnapshot.byCve[cveId];
    const item = buildChangeItem(cveId, prev, current, prevSnapshot, currentSnapshot, publicIntelligenceVersion);
    if (item) items.push(item);
    if (items.length >= changeItemsHardCap) break;
  }

  // Sort items by (categoryOrder, classificationOrder, cveId).
  items.sort((a, b) => {
    const catA = primaryCategory(a.classifications);
    const catB = primaryCategory(b.classifications);
    if (catA !== catB) return PANEL_CATEGORIES.indexOf(catA) - PANEL_CATEGORIES.indexOf(catB);
    const clsA = a.classifications[0];
    const clsB = b.classifications[0];
    if (clsA !== clsB) return (CLASSIFICATION_INDEX[clsA] || 0) - (CLASSIFICATION_INDEX[clsB] || 0);
    return a.cveId < b.cveId ? -1 : a.cveId > b.cveId ? 1 : 0;
  });

  // Compute comparable/suppressed axes.
  const allAxes = ['kev', 'severity-class', 'epss', 'ssvc', 'github-advisory', 'first-patched', 'osv', 'cvss-source'];
  const comparableAxes = [];
  const suppressedAxes = [];
  for (const axis of allAxes) {
    const key = axisToProviderKey(axis);
    const prevComp = prevSnapshot ? isFullyComparable(prevSnapshot, key) : false;
    const curComp = isFullyComparable(currentSnapshot, key);
    if (prevComp && curComp) comparableAxes.push(axis);
    else if (prevComp !== curComp || !prevComp || !curComp) {
      suppressedAxes.push({ axis, reason: !prevComp && !curComp ? 'unavailable in both snapshots' : 'inconsistent' });
    }
  }

  // Compute aggregate summary.
  const summary = emptySummary();
  for (const item of items) {
    for (const cls of item.classifications) {
      switch (cls) {
        case 'cve-newly-tracked': summary.newlyTracked++; break;
        case 'cve-no-longer-tracked': summary.noLongerTracked++; break;
        case 'kev-newly-present':
        case 'ssvc-data-newly-available':
        case 'github-advisory-newly-available':
        case 'first-patched-newly-available':
        case 'osv-record-newly-correlated':
          summary.factNewlyAvailable++; break;
        case 'severity-class-changed':
        case 'cvss-source-or-version-changed':
        case 'epss-materially-increased':
        case 'epss-materially-decreased':
        case 'ssvc-state-changed':
        case 'osv-record-set-changed':
        case 'affected-package-or-range-changed':
          summary.factChanged++; break;
        case 'kev-no-longer-present':
        case 'github-advisory-no-longer-available':
        case 'first-patched-no-longer-available':
        case 'osv-record-removed':
        case 'withdrawn':
          summary.factNoLongerPresent++; break;
      }
      if (cls === 'epss-materially-increased') summary.epssMateriallyIncreased++;
      if (cls === 'epss-materially-decreased') summary.epssMateriallyDecreased++;
    }
  }

  return {
    items,
    summary,
    comparableAxes,
    suppressedAxes,
    partial: false,
    reasons: [],
    comparesFreshBase: !!prevSnapshot,
  };
}

function emptySummary() {
  return {
    newlyTracked: 0,
    noLongerTracked: 0,
    factNewlyAvailable: 0,
    factChanged: 0,
    factNoLongerPresent: 0,
    providerStatusChanged: 0,
    epssMateriallyIncreased: 0,
    epssMateriallyDecreased: 0,
  };
}

function axisToProviderKey(axis) {
  switch (axis) {
    case 'kev': return 'cisaKev';
    case 'severity-class':
    case 'cvss-source': return 'nvd';
    case 'epss': return 'firstEpss';
    case 'ssvc': return 'ssvc';
    case 'github-advisory':
    case 'first-patched': return 'githubAdvisory';
    case 'osv': return 'osv';
    default: return axis;
  }
}

function primaryCategory(classifications) {
  for (const cls of classifications) {
    const cat = classificationToCategory(cls);
    if (cat) return cat;
  }
  return 'fact-changed'; // default; should not happen
}

/**
 * Filter the change items by a panel category. Returns
 * the deterministic first N items (sorted by the
 * canonical order) plus a totalMatching + truncated
 * disclosure.
 */
export function filterByCategory(items, category, limit = 25) {
  if (!Array.isArray(items)) return { items: [], totalMatching: 0, truncated: { shown: 0, total: 0 } };
  const matched = items.filter((it) => Array.isArray(it.classifications) && it.classifications.some((c) => classificationToCategory(c) === category));
  const capped = matched.slice(0, limit);
  return {
    items: capped,
    totalMatching: matched.length,
    truncated: { shown: capped.length, total: matched.length },
  };
}
