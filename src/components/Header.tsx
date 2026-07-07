import {
  Briefcase,
  Clock,
  Database,
  FlaskConical,
  Radar,
  ShieldCheck,
} from 'lucide-react';
import type { ReactNode } from 'react';
import type { FetchResult } from '../services/vulnerabilityService';
import type { Vulnerability } from '../types/vulnerability';
import { formatRelative } from '../utils/format';

interface HeaderProps {
  meta: FetchResult<Vulnerability[]> | null;
}

type Tone = 'good' | 'info' | 'neutral';

const TONE_DOT: Record<Tone, string> = {
  good: 'bg-radar-accent2',
  info: 'bg-radar-accent',
  neutral: 'bg-radar-dim',
};

const TONE_CHIP: Record<Tone, string> = {
  good: 'border-radar-accent2/30 bg-radar-accent2/5 text-radar-accent2',
  info: 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent',
  neutral: 'border-radar-border bg-radar-panel2/60 text-radar-muted',
};

function StatusPill({
  icon,
  label,
  tone,
  pulse,
  title,
}: {
  icon: ReactNode;
  label: string;
  tone: Tone;
  pulse?: boolean;
  title?: string;
}) {
  return (
    <div
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${TONE_CHIP[tone]}`}
      title={title}
    >
      <span
        className={[
          'h-1.5 w-1.5 rounded-full',
          TONE_DOT[tone],
          pulse ? 'animate-pulseDot' : '',
        ].join(' ')}
      />
      {icon}
      <span>{label}</span>
    </div>
  );
}

function MetaBadge({
  icon,
  label,
  tone,
}: {
  icon: ReactNode;
  label: string;
  tone: 'accent' | 'warn';
}) {
  const toneClass =
    tone === 'accent'
      ? 'border-radar-accent/30 bg-radar-accent/5 text-radar-accent'
      : 'border-radar-warn/30 bg-radar-warn/5 text-radar-warn';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${toneClass}`}
    >
      {icon}
      {label}
    </span>
  );
}

export default function Header({ meta }: HeaderProps) {
  const fetchedAt = meta?.fetchedAt ? formatRelative(meta.fetchedAt) : '—';
  const sourceLabel = meta?.source ?? 'loading';

  return (
    <header className="relative isolate overflow-hidden border-b border-radar-border bg-radar-bg/85 backdrop-blur-md">
      {/*
        Decorative background: dot grid + two soft glow blobs.
        Sits behind the content via `-z-10`. Subtle, never loud.
      */}
      <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden>
        <div className="absolute inset-0 opacity-[0.06] [background-image:radial-gradient(rgba(148,163,184,0.9)_1px,transparent_1px)] [background-size:22px_22px]" />
        <div className="absolute -top-32 right-[-8%] h-64 w-[28rem] rounded-full bg-radar-accent/12 blur-3xl" />
        <div className="absolute -bottom-24 left-[5%] h-48 w-[24rem] rounded-full bg-radar-accent2/10 blur-3xl" />
      </div>

      {/* Main hero area — single, clean, no top status strip. */}
      <div className="mx-auto max-w-[1400px] px-4 py-7 lg:px-8 lg:py-9">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between lg:gap-12">
          {/* Brand */}
          <div className="flex min-w-0 items-start gap-4">
            <div className="relative grid h-14 w-14 shrink-0 place-items-center rounded-xl border border-radar-borderStrong bg-radar-panel2 shadow-glow lg:h-16 lg:w-16">
              <Radar className="h-7 w-7 text-radar-accent lg:h-8 lg:w-8" />
              <span className="pointer-events-none absolute inset-0 rounded-xl ring-1 ring-radar-accent/20" />
              <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-radar-accent shadow-[0_0_8px_rgba(34,211,238,0.7)] animate-pulseDot" />
            </div>
            <div className="min-w-0 flex-1">
              <h1 className="text-[1.65rem] font-bold leading-[1.1] tracking-tight text-radar-text sm:text-3xl lg:text-[2.4rem]">
                ThreatPulse Radar
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-radar-muted sm:text-[0.95rem]">
                Defensive vulnerability intelligence dashboard for tracking risk,
                exploitation signals, and remediation priorities.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <MetaBadge
                  icon={<Briefcase className="h-3 w-3" />}
                  label="Portfolio Project"
                  tone="accent"
                />
                <MetaBadge
                  icon={<FlaskConical className="h-3 w-3" />}
                  label="Mock Data Mode"
                  tone="warn"
                />
              </div>
            </div>
          </div>

          {/* Status column */}
          <div className="flex flex-row flex-wrap gap-2 lg:flex-col lg:items-end lg:gap-2">
            <StatusPill
              icon={<ShieldCheck className="h-3 w-3" />}
              label="Defensive use only"
              tone="good"
              pulse
              title="This dashboard is for defensive security work only"
            />
            <StatusPill
              icon={<Database className="h-3 w-3" />}
              label={`Source: ${sourceLabel}`}
              tone="info"
              title="Current data source"
            />
            <StatusPill
              icon={<Clock className="h-3 w-3" />}
              label={`Last refresh: ${fetchedAt}`}
              tone="neutral"
              title="When the dataset was last fetched"
            />
          </div>
        </div>
      </div>
    </header>
  );
}
