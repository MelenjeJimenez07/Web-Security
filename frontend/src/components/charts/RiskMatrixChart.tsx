import { useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, SEVERITY_META } from "@/lib/utils";
import type { Finding } from "@/types/api";

interface RiskMatrixChartProps {
  findings: Finding[];
}

const AXIS_LABELS: Record<number, string> = {
  1: "Muy bajo",
  2: "Bajo",
  3: "Medio",
  4: "Alto",
  5: "Muy alto",
};

function computeRiskPosition(finding: Finding): { likelihood: number; impact: number } {
  const cvss = finding.cvss_score;
  const mod = finding.module_key;

  switch (finding.severity) {
    case "critical":
      return { impact: 5, likelihood: cvss !== null && cvss >= 9.5 ? 5 : 4 };
    case "high":
      return {
        impact: 4,
        likelihood:
          (mod === "dns_passive" || mod === "tech_supply_chain") && (cvss === null || cvss < 8.0)
            ? 3
            : 4,
      };
    case "medium":
      return { impact: 3, likelihood: 3 };
    case "low":
      return { impact: 2, likelihood: mod === "http_headers" || mod === "dns_passive" ? 3 : 2 };
    default:
      return { impact: 1, likelihood: 2 };
  }
}

function zoneMeta(likelihood: number, impact: number): { label: string; cellClass: string } {
  const product = likelihood * impact;
  if (product >= 15) {
    return {
      label: "Crítico",
      cellClass: "border-red-500/40 bg-red-500/20 text-red-200 hover:bg-red-500/30",
    };
  }
  if (product >= 10) {
    return {
      label: "Alto",
      cellClass: "border-orange-500/40 bg-orange-500/20 text-orange-200 hover:bg-orange-500/30",
    };
  }
  if (product >= 5) {
    return {
      label: "Medio",
      cellClass: "border-amber-500/40 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25",
    };
  }
  if (product >= 3) {
    return {
      label: "Bajo",
      cellClass: "border-sky-500/35 bg-sky-500/15 text-sky-200 hover:bg-sky-500/25",
    };
  }
  return {
    label: "Muy bajo",
    cellClass: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20",
  };
}

export function RiskMatrixChart({ findings }: RiskMatrixChartProps) {
  const [selectedCell, setSelectedCell] = useState<string | null>(null);

  const buckets = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const finding of findings) {
      const { likelihood, impact } = computeRiskPosition(finding);
      const key = `${likelihood}-${impact}`;
      const current = map.get(key) ?? [];
      current.push(finding);
      map.set(key, current);
    }
    return map;
  }, [findings]);

  const activeFindings = selectedCell ? buckets.get(selectedCell) ?? [] : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Matriz de Riesgo 5×5 (Probabilidad × Impacto)</CardTitle>
        <CardDescription>
          Distribución cualitativa de hallazgos por nivel de probabilidad e impacto. Haz clic en una celda con hallazgos para ver el detalle.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[540px] border-separate border-spacing-1.5 text-center text-xs">
            <thead>
              <tr>
                <th className="w-32 rounded bg-slate-900/90 px-2 py-2 text-left font-medium text-slate-400">
                  Prob. \ Impacto
                </th>
                {[1, 2, 3, 4, 5].map((impact) => (
                  <th
                    key={impact}
                    className="rounded bg-slate-900/90 px-2 py-2 font-medium text-slate-300"
                  >
                    {AXIS_LABELS[impact]} ({impact})
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[5, 4, 3, 2, 1].map((likelihood) => (
                <tr key={likelihood}>
                  <th className="rounded bg-slate-900/90 px-2.5 py-2 text-left font-medium text-slate-300">
                    {AXIS_LABELS[likelihood]} ({likelihood})
                  </th>
                  {[1, 2, 3, 4, 5].map((impact) => {
                    const key = `${likelihood}-${impact}`;
                    const items = buckets.get(key) ?? [];
                    const { label, cellClass } = zoneMeta(likelihood, impact);
                    const isSelected = selectedCell === key;
                    return (
                      <td key={key}>
                        <button
                          type="button"
                          onClick={() => setSelectedCell(isSelected ? null : key)}
                          className={cn(
                            "flex w-full flex-col items-center justify-center rounded-md border px-2 py-2.5 transition",
                            cellClass,
                            isSelected && "ring-2 ring-sky-400"
                          )}
                        >
                          <span className="font-mono text-base font-bold">{items.length}</span>
                          <span className="text-[10px] opacity-85">{label}</span>
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selectedCell && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <p className="mb-2 text-xs font-semibold text-slate-300">
              Hallazgos en celda seleccionada ({activeFindings.length}):
            </p>
            {activeFindings.length === 0 ? (
              <p className="text-xs text-slate-500">Sin hallazgos ubicados en esta celda.</p>
            ) : (
              <ul className="space-y-1.5">
                {activeFindings.map((item) => (
                  <li
                    key={item.id}
                    className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-200"
                  >
                    <span>
                      <span className="mr-2 font-mono text-sky-300">{item.owasp_category_code}</span>
                      {item.title}
                    </span>
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                        SEVERITY_META[item.severity].badgeClass
                      )}
                    >
                      {SEVERITY_META[item.severity].label}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
