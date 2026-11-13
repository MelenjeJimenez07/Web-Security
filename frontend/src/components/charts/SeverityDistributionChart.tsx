import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_META } from "@/lib/utils";
import type { SeverityLevel } from "@/types/api";

interface SeverityDistributionChartProps {
  distribution: Record<SeverityLevel, number>;
  title?: string;
  description?: string;
}

const ORDERED_SEVERITIES: SeverityLevel[] = ["critical", "high", "medium", "low", "info"];

export function SeverityDistributionChart({
  distribution,
  title = "Distribución por Severidad",
  description = "Proporción de hallazgos clasificados según impacto técnico.",
}: SeverityDistributionChartProps) {
  const total = ORDERED_SEVERITIES.reduce((acc, sev) => acc + (distribution[sev] ?? 0), 0);

  const chartData = ORDERED_SEVERITIES.map((sev) => ({
    key: sev,
    name: SEVERITY_META[sev].label,
    value: distribution[sev] ?? 0,
    color: SEVERITY_META[sev].color,
  })).filter((item) => item.value > 0);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">
            Sin hallazgos registrados todavía.
          </div>
        ) : (
          <div className="grid grid-cols-1 items-center gap-4 sm:grid-cols-2">
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
                    outerRadius={84}
                    paddingAngle={3}
                    stroke="#0f172a"
                    strokeWidth={2}
                  >
                    {chartData.map((entry) => (
                      <Cell key={entry.key} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      color: "#f8fafc",
                      fontSize: "12px",
                    }}
                    formatter={(value, name) => [
                      `${value ?? 0} hallazgos`,
                      String(name ?? ""),
                    ]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="space-y-2.5">
              {ORDERED_SEVERITIES.map((sev) => {
                const count = distribution[sev] ?? 0;
                const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                return (
                  <div key={sev} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-2 font-medium text-slate-200">
                        <span
                          className="inline-block h-2.5 w-2.5 rounded-full"
                          style={{ backgroundColor: SEVERITY_META[sev].color }}
                        />
                        {SEVERITY_META[sev].label}
                      </span>
                      <span className="font-mono text-slate-400">
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: SEVERITY_META[sev].color,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
