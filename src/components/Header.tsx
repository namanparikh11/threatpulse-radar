import { Activity, Github, Radar, ShieldCheck } from 'lucide-react';
import type { FetchResult } from '../services/vulnerabilityService';
import type { Vulnerability } from '../types/vulnerability';
import { formatRelative } from '../utils/format';

interface HeaderProps {
  meta: FetchResult<Vulnerability[]> | null;
}

export default function Header({ meta }: HeaderProps) {
  const fetchedAt = meta?.fetchedAt ? formatRelative(meta.fetchedAt) : '—';
  return (
    <header className="sticky top-0 z-30 border-b border-radar-border/80 bg-radar-bg/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4 px-4 py-3 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="relative grid h-9 w-9 place-items-center rounded-lg border border-radar-borderStrong bg-radar-panel2">
            <Radar className="h-5 w-5 text-radar-accent" />
            <span className="pointer-events-none absolute inset-0 rounded-lg ring-1 ring-radar-accent/20" />
            <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-radar-accent animate-pulseDot" />
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <h1 className="text-base font-semibold tracking-tight text-radar-text">
                ThreatPulse Radar
              </h1>
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-radar-dim">
                v1.0
              </span>
            </div>
            <p className="text-xs text-radar-muted">
              Vulnerability intelligence for defensive security teams
            </p>
          </div>
        </div>

        <div className="hidden items-center gap-3 text-xs text-radar-muted md:flex">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-radar-accent2" />
            <span>Defensive use only</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-radar-accent" />
            <span>Source: {meta?.source ?? 'loading'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-radar-accent2 animate-pulseDot" />
            <span>Last refresh: {fetchedAt}</span>
          </div>
        </div>

        <a
          href="https://github.com"
          target="_blank"
          rel="noreferrer noopener"
          className="focus-ring hidden items-center gap-1.5 rounded-md border border-radar-borderStrong bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-muted transition hover:text-radar-text lg:inline-flex"
          aria-label="View source (placeholder)"
        >
          <Github className="h-3.5 w-3.5" />
          Source
        </a>
      </div>
    </header>
  );
}
