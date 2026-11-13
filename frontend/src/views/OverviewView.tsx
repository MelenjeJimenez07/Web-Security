import {
  Activity,
  AlertTriangle,
  ArrowRight,
  GlobeLock,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { OwaspTop10Chart } from "@/components/charts/OwaspTop10Chart";
import { SeverityDistributionChart } from "@/components/charts/SeverityDistributionChart";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AUDIT_STATUS_META, cn, formatDateTime, gradeBadgeClass } from "@/lib/utils";
import type { DashboardStats } from "@/types/api";

interface OverviewViewProps {
  stats: DashboardStats | null;
  loading: boolean;
  onRefresh: () => void;
  onNavigateLaunch: () => void;
  onNavigateAssets: () => void;
  onOpenAudit: (auditId: string) => void;
}

export function OverviewView({
  stats,
  loading,
  onRefresh,
  onNavigateLaunch,
  onNavigateAssets,
  onOpenAudit,
}: OverviewViewProps) {
  const critHighCount =
    (stats?.severity_distribution.critical ?? 0) + (stats?.severity_distribution.high ?? 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Centro de Control AppSec
          </h1>
          <p className="text-sm text-slate-400">
            Diagnóstico centralizado de superficie web e infraestructura mapeado a OWASP Top 10:2025.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={onRefresh} disabled={loading}>
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
            Actualizar
          </Button>
          <Button variant="secondary" size="sm" onClick={onNavigateAssets}>
            <GlobeLock className="h-3.5 w-3.5" />
            Gestionar Activos
          </Button>
          <Button size="sm" onClick={onNavigateLaunch}>
            <Play className="h-3.5 w-3.5" />
            Nueva Auditoría
          </Button>
        </div>
      </div>

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardContent className="flex items-center justify-between p-5">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Activos Registrados
              </p>
              <p className="mt-1.5 text-3xl font-bold text-slate-100">
                {stats?.total_assets ?? 0}
              </p>
              <p className="mt-1 text-xs text-emerald-400">
                {stats?.verified_assets ?? 0} verificado(s)
              </p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400">
              <ShieldCheck className="h-6 w-6" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center justify-between p-5">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Auditorías Ejecutadas
              </p>
              <p className="mt-1.5 text-3xl font-bold text-slate-100">
                {stats?.total_audits ?? 0}
              </p>
              <p className="mt-1 text-xs text-sky-400">
                {stats?.active_audits ?? 0} en progreso
              </p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-500/15 text-sky-400">
              <Activity className="h-6 w-6" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center justify-between p-5">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Críticos y Altos
              </p>
              <p className="mt-1.5 text-3xl font-bold text-red-400">{critHighCount}</p>
              <p className="mt-1 text-xs text-slate-400">
                {stats?.severity_distribution.critical ?? 0} críticos •{" "}
                {stats?.severity_distribution.high ?? 0} altos
              </p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-red-500/15 text-red-400">
              <AlertTriangle className="h-6 w-6" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex items-center justify-between p-5">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                Hallazgos Totales
              </p>
              <p className="mt-1.5 text-3xl font-bold text-slate-100">
                {stats?.total_findings ?? 0}
              </p>
              <p className="mt-1 text-xs text-amber-300">
                {stats?.severity_distribution.medium ?? 0} medios •{" "}
                {stats?.severity_distribution.low ?? 0} bajos
              </p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-amber-500/15 text-amber-300">
              <ShieldAlert className="h-6 w-6" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="xl:col-span-5">
          <SeverityDistributionChart
            distribution={
              stats?.severity_distribution ?? {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
              }
            }
          />
        </div>
        <div className="xl:col-span-7">
          <OwaspTop10Chart data={stats?.owasp_distribution ?? []} />
        </div>
      </div>

      {/* Recent Audits Table */}
      <Card>
        <CardHeader>
          <CardTitle>Auditorías Recientes</CardTitle>
          <CardDescription>
            Historial más reciente de escaneos y calificaciones de postura de seguridad.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!stats || stats.recent_audits.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-800 py-10 text-center text-sm text-slate-400">
              Aún no se han ejecutado auditorías. Registra un activo y lanza tu primer análisis.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-800 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="py-2.5 pr-4">Activo</th>
                    <th className="py-2.5 pr-4">Perfil</th>
                    <th className="py-2.5 pr-4">Estado</th>
                    <th className="py-2.5 pr-4">Nota</th>
                    <th className="py-2.5 pr-4">Hallazgos</th>
                    <th className="py-2.5 pr-4">Fecha</th>
                    <th className="py-2.5 text-right">Detalle</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {stats.recent_audits.map((run) => {
                    const st = AUDIT_STATUS_META[run.status];
                    return (
                      <tr key={run.id} className="hover:bg-slate-800/30">
                        <td className="py-3 pr-4">
                          <p className="font-medium text-slate-100">
                            {run.asset_name || "Activo"}
                          </p>
                          <p className="font-mono text-xs text-slate-400">
                            {run.asset_target || run.asset_id}
                          </p>
                        </td>
                        <td className="py-3 pr-4">
                          <Badge variant="secondary" className="font-mono text-[11px]">
                            {run.scan_profile}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4">
                          <span
                            className={cn(
                              "inline-flex rounded-md border px-2 py-0.5 text-xs font-medium",
                              st.badgeClass
                            )}
                          >
                            {st.label} ({run.progress_percent}%)
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <span
                            className={cn(
                              "inline-flex rounded-md border px-2 py-0.5 font-mono text-xs font-bold",
                              gradeBadgeClass(run.security_grade)
                            )}
                          >
                            {run.security_grade || "—"}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-300">
                          {run.total_findings}
                          {run.critical_count > 0 && (
                            <span className="ml-1.5 text-red-400">({run.critical_count} crit)</span>
                          )}
                        </td>
                        <td className="py-3 pr-4 text-xs text-slate-400">
                          {formatDateTime(run.created_at)}
                        </td>
                        <td className="py-3 text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onOpenAudit(run.id)}
                          >
                            Inspeccionar
                            <ArrowRight className="h-3.5 w-3.5" />
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
