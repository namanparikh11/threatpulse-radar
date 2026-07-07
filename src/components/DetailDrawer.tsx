import { ExternalLink, ShieldCheck, X } from 'lucide-react';
import { useEffect } from 'react';
import type { Vulnerability } from '../types/vulnerability';
import { SEVERITY_BADGE } from '../utils/severity';
import { formatCvss, formatDate, formatEpss, formatRelative } from '../utils/format';

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
