import {
  AlertOctagon,
  AlertTriangle,
  CalendarClock,
  Crosshair,
  Database,
  ShieldAlert,
} from 'lucide-react';
import type { DashboardStats } from '../types/vulnerability';
import { formatEpss, formatNumber } from '../utils/format';

interface StatsCardsProps {
  stats: DashboardStats;
}

interface Card {
  label: string;
  value: string;
  hint?: string;
  Icon: React.ComponentType<{ className?: string }>;
  accent: string; // tailwind class for the icon color
  ring: string; // tailwind class for the ring
}

export default function StatsCards({ stats }: StatsCardsProps) {
  const cards: Card[] = [
    {
      label: 'Total vulnerabilities',
      value: formatNumber(stats.total),
      hint: 'Tracked in the current dataset',
      Icon: Database,
      accent: 'text-radar-accent',
      ring: 'ring-radar-accent/20',
    },
    {
      label: 'Critical',
      value: formatNumber(stats.critical),
      hint: 'CVSS ≥ 9.0',
      Icon: AlertOctagon,
      accent: 'text-radar-critical',
      ring: 'ring-radar-critical/20',
    },
    {
      label: 'High',
      value: formatNumber(stats.high),
      hint: 'CVSS 7.0 – 8.9',
      Icon: AlertTriangle,
      accent: 'text-radar-high',
      ring: 'ring-radar-high/20',
    },
    {
      label: 'Known exploited (KEV)',
      value: formatNumber(stats.knownExploited),
      hint: 'Listed in CISA KEV',
      Icon: ShieldAlert,
      accent: 'text-radar-warn',
      ring: 'ring-radar-warn/20',
    },
    {
      label: 'Average EPSS',
      value: formatEpss(stats.averageEpss),
      hint: 'Probability of exploitation',
      Icon: Crosshair,
      accent: 'text-radar-accent2',
      ring: 'ring-radar-accent2/20',
    },
    {
      label: 'New this week',
      value: formatNumber(stats.newThisWeek),
      hint: 'Published in last 7 days',
      Icon: CalendarClock,
      accent: 'text-radar-low',
      ring: 'ring-radar-low/20',
    },
  ];

  return (
    <section
      className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6"
      aria-label="Dashboard statistics"
    >
      {cards.map(({ label, value, hint, Icon, accent, ring }) => (
        <div
          key={label}
          className={`panel relative overflow-hidden p-4 transition hover:ring-1 ${ring}`}
        >
          <div className="flex items-start justify-between">
            <span className="stat-label">{label}</span>
            <Icon className={`h-4 w-4 ${accent}`} />
          </div>
          <div className="stat-num mt-2">{value}</div>
          {hint && <div className="mt-1 text-[11px] text-radar-dim">{hint}</div>}
          <div
            className={`pointer-events-none absolute -bottom-6 -right-6 h-16 w-16 rounded-full opacity-10 blur-2xl ${accent.replace(
              'text-',
              'bg-'
            )}`}
          />
        </div>
      ))}
    </section>
  );
}
