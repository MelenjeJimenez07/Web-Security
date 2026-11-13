import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_META } from "@/lib/utils";
import type { OwaspDistributionItem } from "@/types/api";

interface OwaspTop10ChartProps {
  data: OwaspDistributionItem[];
  title?: string;
  description?: string;
}

interface CustomTooltipPayload {
  payload?: OwaspDistributionItem;
}

function OwaspTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: CustomTooltipPayload[];
}) {
  if (!active || !payload || payload.length === 0 || !payload[0]?.payload) {
    return null;
  }
  const item = payload[0].payload;
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-950/95 p-3 text-xs shadow-xl">
      <p className="font-semibold text-sky-300">
        {item.code} — {item.name_es}
      </p>
      <p className="mb-2 text-[11px] text-slate-400">{item.name}</p>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono">
        <span className="text-red-400">Crítico: {item.critical}</span>
        <span className="text-orange-400">Alto: {item.high}</span>
        <span className="text-amber-300">Medio: {item.medium}</span>
        <span className="text-cyan-300">Bajo: {item.low}</span>
        <span className="text-slate-300">Info: {item.info}</span>
        <span className="font-bold text-slate-100">Total: {item.count}</span>
      </div>
    </div>
  );
}

export function OwaspTop10Chart({
  data,
  title = "Mapeo OWASP Top 10:2025",
  description = "Distribución acumulada de hallazgos por categoría oficial OWASP Top 10:2025 y severidad.",
}: OwaspTop10ChartProps) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 12, left: -16, bottom: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="code"
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                axisLine={{ stroke: "#334155" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                axisLine={{ stroke: "#334155" }}
                tickLine={false}
              />
              <Tooltip content={<OwaspTooltip />} cursor={{ fill: "rgba(56, 189, 248, 0.07)" }} />
              <Legend wrapperStyle={{ fontSize: "12px", paddingTop: "8px" }} />
              <Bar dataKey="critical" name="Crítico" stackId="a" fill={SEVERITY_META.critical.color} />
              <Bar dataKey="high" name="Alto" stackId="a" fill={SEVERITY_META.high.color} />
              <Bar dataKey="medium" name="Medio" stackId="a" fill={SEVERITY_META.medium.color} />
              <Bar dataKey="low" name="Bajo" stackId="a" fill={SEVERITY_META.low.color} />
              <Bar
                dataKey="info"
                name="Info"
                stackId="a"
                fill={SEVERITY_META.info.color}
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
