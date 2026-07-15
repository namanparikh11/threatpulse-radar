import { ClipboardList, ExternalLink, Package, ShieldCheck, X, Box } from 'lucide-react';
import { useEffect } from 'react';
import type {
  GithubAdvisory,
  GithubAdvisoryPackage,
  SsvcAutomatable,
  SsvcExploitation,
  SsvcTechnicalImpact,
  Vulnerability,
} from '../types/vulnerability';
import { SEVERITY_BADGE } from '../utils/severity';
import { formatAbsolute, formatCvss, formatDate, formatEpss, formatRelative } from '../utils/format';
import OsvContext from './drawer/OsvContext';

interface DetailDrawerProps {
  vuln: Vulnerability | null;
  onClose: () => void;
}

export default function DetailDrawer({ vuln, onClose }: DetailDrawerProps) {
  // Close on ESC
  useEffect(() => {
    if (!vuln) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [vuln, onClose]);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        className={[
          'fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity',
          vuln ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none',
        ].join(' ')}
        aria-hidden={!vuln}
      />
      {/* Drawer */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={vuln ? `Details for ${vuln.cveId}` : 'Vulnerability details'}
        className={[
          'fixed inset-y-0 right-0 z-50 w-full max-w-[520px] transform border-l border-radar-border bg-radar-panel shadow-2xl transition-transform',
          vuln ? 'translate-x-0' : 'translate-x-full',
        ].join(' ')}
      >
        {vuln && <DrawerBody vuln={vuln} onClose={onClose} />}
      </aside>
    </>
  );
}

function DrawerBody({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-start justify-between gap-3 border-b border-radar-border bg-radar-panel2/60 px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-radar-accent">{vuln.cveId}</span>
            <span className={`chip ${SEVERITY_BADGE[vuln.severity]}`}>{vuln.severity}</span>
            {vuln.kev && (
              <span className="chip border-radar-warn/40 bg-radar-warn/10 text-radar-warn">
                KEV
              </span>
            )}
          </div>
          <h2 className="mt-2 text-base font-semibold text-radar-text">{vuln.summary}</h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="focus-ring rounded-md border border-radar-border p-1.5 text-radar-muted hover:text-radar-text"
          aria-label="Close details"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex-1 overflow-y-auto px-5 py-4 text-sm">
        <Section title="Overview">
          <p className="text-radar-text/90">{vuln.description}</p>
        </Section>

        <Section title="Metrics">
          <div className="grid grid-cols-2 gap-3">
            <Metric label="CVSS score" value={formatCvss(vuln.cvssScore)} />
            <Metric label="EPSS probability" value={formatEpss(vuln.epssProbability)} />
            <Metric label="Published" value={formatDate(vuln.publishedDate)} hint={formatRelative(vuln.publishedDate)} />
            <Metric label="Source" value={vuln.source} />
          </div>
        </Section>

        <Section title="Affected">
          <div className="rounded-md border border-radar-border bg-radar-panel2/60 p-3">
            <div className="text-radar-text">{vuln.vendor}</div>
            <div className="text-xs text-radar-dim">{vuln.product}</div>
          </div>
        </Section>

        <Section
          title="Recommended defensive action"
          icon={<ShieldCheck className="h-3.5 w-3.5 text-radar-accent2" />}
        >
          <p className="rounded-md border border-radar-accent2/20 bg-radar-accent2/5 p-3 text-radar-text/90">
            {vuln.recommendedAction}
          </p>
        </Section>

        <Section
          title="CISA decision context"
          icon={<ClipboardList className="h-3.5 w-3.5 text-radar-accent" />}
        >
          <SsvcContext vuln={vuln} />
        </Section>

        <Section
          title="Package remediation context"
          icon={<Package className="h-3.5 w-3.5 text-radar-accent" />}
        >
          <GithubAdvisoryContext vuln={vuln} />
        </Section>

        <Section
          title="OSV package context"
          icon={<Box className="h-3.5 w-3.5 text-radar-accent" />}
        >
          <OsvContext vuln={vuln} />
        </Section>

        <Section title="External references">
          <ul className="space-y-1.5">
            {vuln.externalLinks.map((l) => (
              <li key={l.label}>
                <a
                  href={l.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="focus-ring inline-flex items-center gap-1.5 text-radar-accent underline-offset-2 hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  {l.label}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      </div>
    </div>
  );
}

function Section({
  title,
  children,
  icon,
}: {
  title: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <section className="mb-5">
      <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-radar-muted">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

function Metric({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/60 p-3">
      <div className="stat-label">{label}</div>
      <div className="mt-1 text-radar-text">{value}</div>
      {hint && <div className="text-[11px] text-radar-dim">{hint}</div>}
    </div>
  );
}

/**
 * v5.5: Compact "CISA decision context" panel for the
 * vulnerability detail drawer. Shows the three SSVC
 * decision options (Exploitation, Automatable, Technical
 * Impact) plus the assessment timestamp and the source
 * label ("CISA Vulnrichment"). Rendered only when at
 * least one of the SSVC fields is present; otherwise
 * surfaces the honest "No CISA Vulnrichment assessment
 * available." message.
 *
 * The three decisions are styled with intent-coded tones
 * so the operator can scan them at a glance:
 *   - Exploitation = active  → warn (red)
 *   - Exploitation = poc     → warn (amber)
 *   - Exploitation = none    → info (cyan, neutral)
 *   - Automatable = yes      → warn (amber)
 *   - Automatable = no       → info (cyan)
 *   - Technical Impact = total    → warn (red)
 *   - Technical Impact = partial  → info (cyan)
 *
 * The styling is purely visual aid — the literal value is
 * always rendered so screen readers and copy-paste work
 * cleanly.
 */
function SsvcContext({ vuln }: { vuln: Vulnerability }) {
  const hasSsvc =
    !!vuln.ssvcExploitation ||
    !!vuln.ssvcAutomatable ||
    !!vuln.ssvcTechnicalImpact;

  if (!hasSsvc) {
    return (
      <p className="rounded-md border border-radar-border bg-radar-panel2/60 p-3 text-xs text-radar-muted">
        No CISA Vulnrichment assessment available.
      </p>
    );
  }

  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/60 p-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <SsvcMetric
          label="Exploitation"
          display={formatSsvcExploitation(vuln.ssvcExploitation)}
        />
        <SsvcMetric
          label="Automatable"
          display={formatSsvcAutomatable(vuln.ssvcAutomatable)}
        />
        <SsvcMetric
          label="Technical impact"
          display={formatSsvcTechnicalImpact(vuln.ssvcTechnicalImpact)}
        />
      </div>
      <dl className="mt-3 grid grid-cols-1 gap-2 text-[11px] text-radar-dim sm:grid-cols-2">
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            Assessed
          </dt>
          <dd className="mt-0.5 text-radar-text">
            {vuln.ssvcAssessedAt
              ? formatAbsolute(vuln.ssvcAssessedAt)
              : 'Unknown'}
            {vuln.ssvcVersion ? (
              <span className="ml-1 text-radar-dim">
                (SSVC {vuln.ssvcVersion})
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            Source
          </dt>
          <dd className="mt-0.5 text-radar-text">
            {vuln.ssvcSource ?? 'CISA Vulnrichment'}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function SsvcMetric({
  label,
  display,
}: {
  label: string;
  display: { label: string; tone: string };
}) {
  return (
    <div>
      <div className="stat-label">{label}</div>
      <div className={`mt-1 text-sm font-medium ${display.tone}`}>
        {display.label}
      </div>
    </div>
  );
}

function formatSsvcExploitation(value: SsvcExploitation | undefined) {
  switch (value) {
    case 'active':
      return { label: 'Active', tone: 'text-radar-warn' };
    case 'poc':
      return { label: 'Proof of concept', tone: 'text-radar-warn' };
    case 'none':
      return { label: 'None', tone: 'text-radar-accent' };
    default:
      return { label: 'Unknown', tone: 'text-radar-muted' };
  }
}

function formatSsvcAutomatable(value: SsvcAutomatable | undefined) {
  switch (value) {
    case 'yes':
      return { label: 'Yes', tone: 'text-radar-warn' };
    case 'no':
      return { label: 'No', tone: 'text-radar-accent' };
    default:
      return { label: 'Unknown', tone: 'text-radar-muted' };
  }
}

function formatSsvcTechnicalImpact(value: SsvcTechnicalImpact | undefined) {
  switch (value) {
    case 'total':
      return { label: 'Total', tone: 'text-radar-warn' };
    case 'partial':
      return { label: 'Partial', tone: 'text-radar-accent' };
    default:
      return { label: 'Unknown', tone: 'text-radar-muted' };
  }
}

/**
 * v5.6: Compact "Package remediation context" panel for the
 * vulnerability detail drawer. Surfaces the GitHub Advisory
 * Database review for the CVE — GHSA id, severity, the
 * most recent GitHub review date, the source label
 * ("GitHub Advisory Database"), and (when present) a
 * per-package breakdown of the ecosystem / package name /
 * affected version range / first patched version.
 *
 * Rendered only when a positive reviewed advisory exists;
 * otherwise the honest empty-state copy "No GitHub-reviewed
 * package advisory available." is shown. The empty state
 * is intentionally NOT styled as an error — partial
 * coverage is a normal state of the incremental backfill,
 * not a failure.
 *
 * Spec contract:
 *   - `ghsaId` / `advisoryUrl` / `advisorySeverity` /
 *     `githubReviewedAt` / `source` come from the
 *     normalized advisory payload (see
 *     `githubAdvisory.mjs#extractReviewedAdvisories`).
 *   - `packages` is a deduplicated, capped-at-5 list of
 *     package entries with `ecosystem` / `name` /
 *     `vulnerableVersionRange` / `firstPatchedVersion`.
 *   - `firstPatchedVersion: null` is rendered as the
 *     explicit neutral copy "First patched version
 *     unavailable." — NEVER as "No fix exists". This
 *     distinction is a hard contract (v5.6 spec
 *     requirement 11).
 *   - The external `advisoryUrl` link uses the normalized
 *     GitHub `html_url`, opens in a new tab, and uses
 *     `rel="noreferrer noopener"` for safety.
 */
function GithubAdvisoryContext({ vuln }: { vuln: Vulnerability }) {
  const advisory = vuln.githubAdvisory;
  if (!advisory || !advisory.ghsaId) {
    return (
      <p className="rounded-md border border-radar-border bg-radar-panel2/60 p-3 text-xs text-radar-muted">
        No GitHub-reviewed package advisory available.
      </p>
    );
  }

  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/60 p-3">
      <dl className="grid grid-cols-1 gap-2 text-[11px] text-radar-dim sm:grid-cols-2">
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            GHSA
          </dt>
          <dd className="mt-0.5">
            {advisory.advisoryUrl ? (
              <a
                href={advisory.advisoryUrl}
                target="_blank"
                rel="noreferrer noopener"
                className="focus-ring inline-flex items-center gap-1.5 text-radar-accent underline-offset-2 hover:underline"
              >
                <ExternalLink className="h-3 w-3" />
                <span className="font-mono">{advisory.ghsaId}</span>
              </a>
            ) : (
              <span className="font-mono text-radar-text">
                {advisory.ghsaId}
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            Severity
          </dt>
          <dd
            className={`mt-0.5 text-sm font-medium ${advisorySeverityTone(
              advisory.advisorySeverity
            )}`}
          >
            {formatAdvisorySeverity(advisory.advisorySeverity)}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            GitHub-reviewed
          </dt>
          <dd className="mt-0.5 text-radar-text">
            {advisory.githubReviewedAt
              ? formatAbsolute(advisory.githubReviewedAt)
              : 'Unknown'}
          </dd>
        </div>
        <div>
          <dt className="font-medium uppercase tracking-wider text-radar-muted">
            Source
          </dt>
          <dd className="mt-0.5 text-radar-text">
            {advisory.source}
          </dd>
        </div>
      </dl>
      {Array.isArray(advisory.packages) && advisory.packages.length > 0 ? (
        <div className="mt-3">
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-radar-muted">
            Affected packages
          </div>
          <ul className="space-y-2">
            {advisory.packages.map((p, idx) => (
              <PackageEntry key={`${p.ecosystem}-${p.name}-${idx}`} pkg={p} />
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function PackageEntry({ pkg }: { pkg: GithubAdvisoryPackage }) {
  return (
    <li className="rounded-md border border-radar-border bg-radar-panel/60 p-2.5">
      <div className="flex items-baseline justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-radar-text">
            <span className="text-radar-muted">{pkg.ecosystem}</span>
            <span className="px-1 text-radar-dim">/</span>
            <span className="font-mono">{pkg.name}</span>
          </div>
          {pkg.vulnerableVersionRange ? (
            <div className="mt-0.5 text-[11px] text-radar-dim">
              <span className="uppercase tracking-wider">Affected:</span>{' '}
              <span className="font-mono">{pkg.vulnerableVersionRange}</span>
            </div>
          ) : null}
        </div>
        <div className="shrink-0 text-right">
          <div className="text-[10px] uppercase tracking-wider text-radar-muted">
            First patched
          </div>
          <div className="mt-0.5 font-mono text-sm text-radar-text">
            {pkg.firstPatchedVersion
              ? pkg.firstPatchedVersion
              : 'unavailable'}
          </div>
        </div>
      </div>
    </li>
  );
}

function formatAdvisorySeverity(value: Vulnerability['githubAdvisory'] extends infer A
  ? A extends { advisorySeverity: infer S }
    ? S
    : never
  : never) {
  switch (value) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return 'Unknown';
  }
}

function advisorySeverityTone(value: GithubAdvisory['advisorySeverity']) {
  switch (value) {
    case 'critical':
      return 'text-radar-warn';
    case 'high':
      return 'text-radar-warn';
    case 'medium':
      return 'text-radar-accent2';
    case 'low':
      return 'text-radar-accent';
    default:
      return 'text-radar-muted';
  }
}
