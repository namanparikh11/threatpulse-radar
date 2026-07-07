import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { TooltipProps } from 'recharts';
import { ShieldAlert } from 'lucide-react';

interface KevChartProps {
  kev: number;
  nonKev: number;
}

export default function KevChart({ kev, nonKev }: KevChartProps) {
  const total = kev + nonKev;
  const data = [
    { name: 'KEV', value: kev, color: '#f59e0b' },
    { name: 'Non-KEV', value: nonKev, color: '#1c2740' },
  ];
  const kevPct = total === 0 ? 0 : Math.round((kev / total) * 100);
  return (
    <div className="panel p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-radar-warn" />
          <h3 className="text-sm font-semibold text-radar-text">KEV vs non-KEV</h3>
        </div>
        <span className="text-[11px] text-radar-dim">{kevPct}% actively exploited</span>
      </div>
      <div className="relative h-56">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip content={<KevTooltip />} />
            <Pie
              data={data}
              innerRadius={50}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
              stroke="#0d1424"
              strokeWidth={2}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold text-radar-text">{kev}</div>
          <div className="text-[10px] uppercase tracking-wider text-radar-dim">KEV records</div>
        </div>
      </div>
    </div>
  );
}

function KevTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload || payload.length === 0) return null;
  const item = payload[0];
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/95 px-2.5 py-1.5 text-xs text-radar-text shadow-lg">
      <div className="font-medium">{item.name}</div>
      <div className="text-radar-muted">
        count: <span className="text-radar-accent">{item.value}</span>
      </div>
    </div>
  );
}
