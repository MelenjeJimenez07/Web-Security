import { useCallback, useEffect, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  Download,
  FileDown,
  FileJson,
  FileText,
  Loader2,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { FindingsExplorer } from "@/components/audits/FindingsExplorer";
import { LiveAuditConsole } from "@/components/audits/LiveAuditConsole";
import { OwaspTop10Chart } from "@/components/charts/OwaspTop10Chart";
import { RiskMatrixChart } from "@/components/charts/RiskMatrixChart";
import { SeverityDistributionChart } from "@/components/charts/SeverityDistributionChart";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { TabsBar } from "@/components/ui/tabs";
import {
  AUDIT_STATUS_META,
  cn,
  formatDateTime,
  gradeBadgeClass,
  isTerminalAuditStatus,
} from "@/lib/utils";
import { ApiError, api } from "@/services/api";
import type {
  AuditReport,
  AuditRunDetail,
  AuditRunSummary,
  Finding,
  FindingStatus,
  ModuleStatus,
  ReportFormat,
  ReportType,
} from "@/types/api";

interface AuditDetailViewProps {
  audits: AuditRunSummary[];
  selectedAuditId: string | null;
  onSelectAudit: (auditId: string | null) => void;
  onRefreshList: () => Promise<void>;
}

function moduleStatusBadge(status: ModuleStatus) {
  switch (status) {
    case "completed":
      return (
        <Badge variant="success">
          <CheckCircle2 className="h-3 w-3" />
          Completado
        </Badge>
      );
    case "running":
      return (
        <Badge variant="default">
          <Loader2 className="h-3 w-3 animate-spin" />
          Ejecutando
        </Badge>
      );
    case "failed":
      return (
        <Badge variant="destructive">
          <XCircle className="h-3 w-3" />
          Error
        </Badge>
      );
    case "skipped":
      return <Badge variant="warning">Omitido</Badge>;
    default:
      return (
        <Badge variant="secondary">
          <Clock className="h-3 w-3" />
          Pendiente
        </Badge>
      );
  }
}

export function AuditDetailView({
  audits,
  selectedAuditId,
  onSelectAudit,
  onRefreshList,
}: AuditDetailViewProps) {
  const [detail, setDetail] = useState<AuditRunDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<AuditReport[]>([]);
  const [reportType, setReportType] = useState<ReportType>("full");
  const [exportingFormat, setExportingFormat] = useState<ReportFormat | null>(null);
  const [activeTab, setActiveTab] = useState<string>("console");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadAuditData = useCallback(async (auditId: string) => {
    setLoading(true);
    setError(null);
    try {
      const [detailData, findingsData, reportsData] = await Promise.all([
        api.getAuditDetail(auditId),
        api.listAuditFindings(auditId),
        api.listAuditReports(auditId),
      ]);
      setDetail(detailData);
      setFindings(findingsData);
      setReports(reportsData);
      if (isTerminalAuditStatus(detailData.status) && findingsData.length > 0) {
        setActiveTab((prev) => (prev === "console" ? "findings" : prev));
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Error cargando detalle de auditoría.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!selectedAuditId) {
      setDetail(null);
      setFindings([]);
      setReports([]);
      return;
    }
    setActiveTab("console");
    void loadAuditData(selectedAuditId);
  }, [selectedAuditId, loadAuditData]);

  const handleExportReport = async (format: ReportFormat) => {
    if (!selectedAuditId) return;
    setError(null);
    setExportingFormat(format);
    try {
      const created = await api.generateAuditReport(selectedAuditId, {
        format,
        report_type: reportType,
      });
      setReports((prev) => [created, ...prev]);
      const link = document.createElement("a");
      link.href = api.getReportDownloadUrl(created.id);
      link.download = created.file_name;
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "No se pudo generar el reporte.");
    } finally {
      setExportingFormat(null);
    }
  };

  const handleFindingStatusChange = async (findingId: string, status: FindingStatus) => {
    const updated = await api.updateFindingStatus(findingId, status);
    setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
  };

  const handleStreamUpdate = useCallback(() => {
    if (!selectedAuditId) return;
    void loadAuditData(selectedAuditId);
    void onRefreshList();
  }, [selectedAuditId, loadAuditData, onRefreshList]);

  if (!selectedAuditId) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              Historial de Auditorías y Consola
            </h1>
            <p className="text-sm text-slate-400">
              Selecciona una ejecución para inspeccionar su consola en vivo, gráficos OWASP y hallazgos.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => void onRefreshList()}>
            <RefreshCw className="h-3.5 w-3.5" />
            Actualizar
          </Button>
        </div>

        <Card>
          <CardContent className="pt-5">
            {audits.length === 0 ? (
              <p className="py-10 text-center text-sm text-slate-500">
                No existen auditorías registradas todavía.
              </p>
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
                      <th className="py-2.5 pr-4">Lanzado por</th>
                      <th className="py-2.5 text-right">Acción</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {audits.map((run) => {
                      const st = AUDIT_STATUS_META[run.status];
                      return (
                        <tr key={run.id} className="hover:bg-slate-800/30">
                          <td className="py-3 pr-4">
                            <p className="font-medium text-slate-100">
                              {run.asset_name || "Activo"}
                            </p>
                            <p className="font-mono text-xs text-sky-300">
                              {run.asset_target || run.asset_id}
                            </p>
                          </td>
                          <td className="py-3 pr-4">
                            <Badge variant="secondary" className="font-mono text-xs">
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
                          </td>
                          <td className="py-3 pr-4 text-xs text-slate-400">
                            {run.requested_by}
                            <div className="text-[11px] text-slate-500">
                              {formatDateTime(run.created_at)}
                            </div>
                          </td>
                          <td className="py-3 text-right">
                            <Button size="sm" onClick={() => onSelectAudit(run.id)}>
                              Abrir Consola / Hallazgos
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={() => onSelectAudit(null)}>
            <ArrowLeft className="h-3.5 w-3.5" />
            Historial
          </Button>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-slate-100">
              {detail?.asset.name || "Cargando auditoría..."}
            </h1>
            <p className="font-mono text-xs text-sky-300">
              {detail?.asset.normalized_target}
              {detail?.asset.resolved_ip ? ` • IP: ${detail.asset.resolved_ip}` : ""}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={loading}
            onClick={() => void loadAuditData(selectedAuditId)}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
            Refrescar
          </Button>

          {detail && isTerminalAuditStatus(detail.status) && (
            <>
              <Select
                aria-label="Tipo de informe"
                value={reportType}
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="h-8 w-36 text-xs"
              >
                <option value="full">Completo</option>
                <option value="executive">Ejecutivo</option>
                <option value="technical">Técnico</option>
              </Select>
              <Button
                size="sm"
                variant="default"
                disabled={exportingFormat !== null}
                onClick={() => void handleExportReport("pdf")}
              >
                <FileDown className="h-3.5 w-3.5" />
                {exportingFormat === "pdf" ? "Generando PDF..." : "Exportar PDF"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={exportingFormat !== null}
                onClick={() => void handleExportReport("docx")}
              >
                <FileText className="h-3.5 w-3.5" />
                {exportingFormat === "docx" ? "Generando DOCX..." : "Exportar DOCX"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={exportingFormat !== null}
                onClick={() => void handleExportReport("json")}
              >
                <FileJson className="h-3.5 w-3.5" />
                {exportingFormat === "json" ? "Generando JSON..." : "Exportar JSON"}
              </Button>
            </>
          )}
        </div>
      </div>

      {error && <Alert variant="destructive">{error}</Alert>}

      {detail && (
        <>
          {/* Summary Banner */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <Card className="lg:col-span-8">
              <CardContent className="grid grid-cols-2 gap-4 p-5 sm:grid-cols-4">
                <div>
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Estado</p>
                  <div className="mt-1.5">
                    <span
                      className={cn(
                        "inline-flex rounded-md border px-2 py-0.5 text-xs font-semibold",
                        AUDIT_STATUS_META[detail.status].badgeClass
                      )}
                    >
                      {AUDIT_STATUS_META[detail.status].label}
                    </span>
                  </div>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Perfil Nmap</p>
                  <p className="mt-1.5 font-mono text-sm font-semibold text-slate-200">
                    {detail.scan_profile}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Hallazgos</p>
                  <p className="mt-1 font-mono text-xl font-bold text-slate-100">
                    {detail.total_findings}
                  </p>
                  <p className="font-mono text-[11px] text-slate-400">
                    C:{detail.critical_count} A:{detail.high_count} M:{detail.medium_count} B:{detail.low_count}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Inicio</p>
                  <p className="mt-1.5 text-xs text-slate-300">
                    {formatDateTime(detail.started_at || detail.created_at)}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card className="lg:col-span-4">
              <CardContent className="flex h-full items-center justify-between p-5">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                    Calificación de Seguridad
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    Puntaje global:{" "}
                    <span className="font-mono font-semibold text-slate-200">
                      {detail.security_score !== null ? `${detail.security_score}/100` : "Pendiente"}
                    </span>
                  </p>
                </div>
                <div
                  className={cn(
                    "flex h-16 w-16 items-center justify-center rounded-xl border-2 font-mono text-3xl font-extrabold",
                    gradeBadgeClass(detail.security_grade)
                  )}
                >
                  {detail.security_grade || "—"}
                </div>
              </CardContent>
            </Card>
          </div>

          {detail.error_message && <Alert variant="destructive">{detail.error_message}</Alert>}

          {/* Module Execution Strip */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
            {detail.module_executions.map((mod) => (
              <Card key={mod.id} className="bg-slate-900/50">
                <CardContent className="space-y-2 p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-sky-300">
                      {mod.module_key}
                    </span>
                    {moduleStatusBadge(mod.status)}
                  </div>
                  <p className="text-xs font-medium text-slate-200 line-clamp-2">
                    {mod.module_name}
                  </p>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span>{mod.findings_count} hallazgo(s)</span>
                    <span>{mod.duration_ms !== null ? `${mod.duration_ms} ms` : "—"}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Tabs */}
          <TabsBar
            activeTab={activeTab}
            onChange={setActiveTab}
            tabs={[
              { id: "console", label: "Consola en Vivo" },
              { id: "findings", label: "Hallazgos y Remediación", badge: findings.length },
              { id: "charts", label: "Gráficos OWASP & Severidad" },
              { id: "telemetry", label: "Telemetría de Módulos" },
              { id: "reports", label: "Reportes Exportados", badge: reports.length },
            ]}
          />

          {activeTab === "console" && (
            <LiveAuditConsole
              auditId={detail.id}
              initialStatus={detail.status}
              initialProgress={detail.progress_percent}
              initialStage={detail.current_stage}
              onStatusUpdate={handleStreamUpdate}
            />
          )}

          {activeTab === "findings" && (
            <FindingsExplorer
              findings={findings}
              onStatusChange={handleFindingStatusChange}
            />
          )}

          {activeTab === "charts" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
                <div className="xl:col-span-5">
                  <SeverityDistributionChart
                    distribution={{
                      critical: detail.critical_count,
                      high: detail.high_count,
                      medium: detail.medium_count,
                      low: detail.low_count,
                      info: detail.info_count,
                    }}
                  />
                </div>
                <div className="xl:col-span-7">
                  <OwaspTop10Chart data={detail.owasp_distribution} />
                </div>
              </div>
              <RiskMatrixChart findings={findings} />
            </div>
          )}

          {activeTab === "telemetry" && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {detail.module_executions.map((mod) => (
                <Card key={mod.id}>
                  <CardHeader>
                    <CardTitle className="text-sm">{mod.module_name}</CardTitle>
                    <CardDescription className="font-mono text-xs">
                      {mod.module_key} • Estado: {mod.status}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {mod.error_detail && (
                      <Alert variant="warning" className="mb-3 text-xs">
                        {mod.error_detail}
                      </Alert>
                    )}
                    <pre className="terminal-scroll max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                      {JSON.stringify(mod.raw_output, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {activeTab === "reports" && (
            <Card>
              <CardHeader>
                <CardTitle>Historial de Reportes Exportados (PDF / DOCX / JSON)</CardTitle>
                <CardDescription>
                  Informes con matriz de cumplimiento OWASP Top 10:2025, matriz de riesgo 5×5, agrupación por severidad y guía de mitigación.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {reports.length === 0 ? (
                  <p className="py-8 text-center text-sm text-slate-400">
                    Aún no se han generado reportes para esta auditoría. Usa los botones "Exportar PDF", "Exportar DOCX" o "Exportar JSON" en la barra superior.
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-800 uppercase text-slate-400">
                        <tr>
                          <th className="py-2.5 pr-4">Archivo</th>
                          <th className="py-2.5 pr-4">Formato</th>
                          <th className="py-2.5 pr-4">Tipo</th>
                          <th className="py-2.5 pr-4">Tamaño</th>
                          <th className="py-2.5 pr-4">SHA-256</th>
                          <th className="py-2.5 pr-4">Fecha</th>
                          <th className="py-2.5 text-right">Descarga</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {reports.map((rep) => (
                          <tr key={rep.id} className="hover:bg-slate-800/30">
                            <td className="py-2.5 pr-4 font-mono text-slate-200">{rep.file_name}</td>
                            <td className="py-2.5 pr-4">
                              <Badge variant={rep.format === "pdf" ? "default" : "secondary"}>
                                {rep.format.toUpperCase()}
                              </Badge>
                            </td>
                            <td className="py-2.5 pr-4 text-slate-300">{rep.report_type}</td>
                            <td className="py-2.5 pr-4 font-mono text-slate-400">
                              {(rep.file_size_bytes / 1024).toFixed(1)} KB
                            </td>
                            <td className="py-2.5 pr-4 font-mono text-slate-400">
                              {rep.sha256_checksum.slice(0, 16)}...
                            </td>
                            <td className="py-2.5 pr-4 text-slate-400">
                              {formatDateTime(rep.created_at)}
                            </td>
                            <td className="py-2.5 text-right">
                              <a
                                href={api.getReportDownloadUrl(rep.id)}
                                download={rep.file_name}
                                className="inline-flex items-center gap-1 rounded-md border border-sky-500/40 bg-sky-500/15 px-2.5 py-1 font-medium text-sky-300 hover:bg-sky-500/25"
                              >
                                <Download className="h-3 w-3" />
                                Descargar
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
