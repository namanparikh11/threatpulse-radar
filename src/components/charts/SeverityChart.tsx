import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from 'recharts';
import type { TooltipProps } from 'recharts';
import { BarChart3 } from 'lucide-react';
import type { Severity } from '../../types/vulnerability';
import { SEVERITY_COLORS, SEVERITY_ORDER } from '../../utils/severity';

interface SeverityChartProps {
  counts: Record<Severity, number>;
}

export default function SeverityChart({ counts }: SeverityChartProps) {
  const data = SEVERITY_ORDER.map((s) => ({ name: s, value: counts[s] ?? 0 }));
  const total = data.reduce((acc, d) => acc + d.value, 0);

  return (
    <ChartPanel title="Severity distribution" subtitle={`${total} records`} icon={<BarChart3 className="h-3.5 w-3.5 text-radar-accent" />}>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" tickLine={false} axisLine={false} fontSize={11} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} />
            <Tooltip
              cursor={{ fill: 'rgba(34, 211, 238, 0.05)' }}
              content={<ChartTooltip />}
            />
            <Bar dataKey="value" radius={[6, 6, 0, 0]}>
              {data.map((d) => (
                <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

interface Bucket {
  name: string;
  count: number;
}

interface EpssChartProps {
  data: Bucket[];
}

export function EpssChart({ data }: EpssChartProps) {
  return (
    <ChartPanel title="EPSS risk distribution" subtitle="Likelihood of exploitation" icon={<BarChart3 className="h-3.5 w-3.5 text-radar-accent2" />}>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" tickLine={false} axisLine={false} fontSize={11} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} />
            <Tooltip cursor={{ fill: 'rgba(34, 211, 238, 0.05)' }} content={<ChartTooltip />} />
            <Bar dataKey="count" radius={[6, 6, 0, 0]} fill="#22d3ee" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </ChartPanel>
  );
}

function ChartPanel({
  title,
  subtitle,
  icon,
  children,
}: {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="panel p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {icon}
          <h3 className="text-sm font-semibold text-radar-text">{title}</h3>
        </div>
        {subtitle && <span className="text-[11px] text-radar-dim">{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function ChartTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/95 px-2.5 py-1.5 text-xs text-radar-text shadow-lg">
      <div className="font-medium">{label}</div>
      <div className="text-radar-muted">
        {payload[0].name}: <span className="text-radar-accent">{payload[0].value}</span>
      </div>
    </div>
  );
}
