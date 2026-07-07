import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { TooltipProps } from 'recharts';
import { TrendingUp } from 'lucide-react';

interface TrendChartProps {
  data: { date: string; count: number }[];
}

export default function TrendChart({ data }: TrendChartProps) {
  const total = data.reduce((acc, d) => acc + d.count, 0);
  return (
    <div className="panel p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <TrendingUp className="h-3.5 w-3.5 text-radar-accent" />
          <h3 className="text-sm font-semibold text-radar-text">Recent vulnerabilities</h3>
        </div>
        <span className="text-[11px] text-radar-dim">{total} new in last 14d</span>
      </div>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
            <defs>
              <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stopColor="#22d3ee" stopOpacity={0.5} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={11} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} />
            <Tooltip
              cursor={{ stroke: 'rgba(34, 211, 238, 0.5)' }}
              content={<TrendTooltip />}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#22d3ee"
              strokeWidth={2}
              fill="url(#trendFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function TrendTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/95 px-2.5 py-1.5 text-xs text-radar-text shadow-lg">
      <div className="font-medium">{label}</div>
      <div className="text-radar-muted">
        count: <span className="text-radar-accent">{payload[0].value}</span>
      </div>
    </div>
  );
}
