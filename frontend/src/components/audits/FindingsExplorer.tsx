import { useMemo, useState } from "react";
import { Check, Copy, ExternalLink, Filter, Search, ShieldAlert, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { cn, FINDING_STATUS_META, SEVERITY_META } from "@/lib/utils";
import type { Finding, FindingStatus, SeverityLevel } from "@/types/api";

interface FindingsExplorerProps {
  findings: Finding[];
  onStatusChange: (findingId: string, status: FindingStatus) => Promise<void>;
}

export function FindingsExplorer({ findings, onStatusChange }: FindingsExplorerProps) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [owaspFilter, setOwaspFilter] = useState<string>("all");
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(findings[0]?.id ?? null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const uniqueOwasp = useMemo(
    () => Array.from(new Set(findings.map((f) => f.owasp_category_code))).sort(),
    [findings]
  );
  const uniqueModules = useMemo(
    () => Array.from(new Set(findings.map((f) => f.module_key))).sort(),
    [findings]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings
      .filter((f) => {
        if (severityFilter !== "all" && f.severity !== severityFilter) return false;
        if (owaspFilter !== "all" && f.owasp_category_code !== owaspFilter) return false;
        if (moduleFilter !== "all" && f.module_key !== moduleFilter) return false;
        if (statusFilter !== "all" && f.status !== statusFilter) return false;
        if (
          q &&
          !f.title.toLowerCase().includes(q) &&
          !f.technical_description.toLowerCase().includes(q) &&
          !(f.affected_component || "").toLowerCase().includes(q) &&
          !f.owasp_category_code.toLowerCase().includes(q)
        ) {
          return false;
        }
        return true;
      })
      .sort((a, b) => SEVERITY_META[a.severity].order - SEVERITY_META[b.severity].order);
  }, [findings, severityFilter, owaspFilter, moduleFilter, statusFilter, search]);

  const selectedFinding =
    filtered.find((f) => f.id === selectedId) || filtered[0] || null;

  const copyText = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Clipboard API unavailable in non-secure context
    }
  };

  const handleStatusUpdate = async (findingId: string, nextStatus: FindingStatus) => {
    setUpdatingId(findingId);
    try {
      await onStatusChange(findingId, nextStatus);
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Filter className="h-4 w-4 text-sky-400" />
            Filtros de Hallazgos ({filtered.length} de {findings.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
            <div className="relative md:col-span-2">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Buscar por título, componente, CVE, OWASP..."
                className="pl-8"
              />
            </div>
            <Select
              aria-label="Filtrar por severidad"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">Todas las severidades</option>
              {(["critical", "high", "medium", "low", "info"] as SeverityLevel[]).map((sev) => (
                <option key={sev} value={sev}>
                  {SEVERITY_META[sev].label}
                </option>
              ))}
            </Select>
            <Select
              aria-label="Filtrar por categoría OWASP"
              value={owaspFilter}
              onChange={(e) => setOwaspFilter(e.target.value)}
            >
              <option value="all">Todas las OWASP 2025</option>
              {uniqueOwasp.map((code) => (
                <option key={code} value={code}>
                  {code}
                </option>
              ))}
            </Select>
            <div className="grid grid-cols-2 gap-2">
              <Select
                aria-label="Filtrar por módulo"
                value={moduleFilter}
                onChange={(e) => setModuleFilter(e.target.value)}
              >
                <option value="all">Módulos</option>
                {uniqueModules.map((mod) => (
                  <option key={mod} value={mod}>
                    {mod}
                  </option>
                ))}
              </Select>
              <Select
                aria-label="Filtrar por estado"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">Estado</option>
                <option value="open">Abierto</option>
                <option value="acknowledged">Reconocido</option>
                <option value="mitigated">Mitigado</option>
                <option value="false_positive">Falso Positivo</option>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {filtered.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-slate-400">
            No se encontraron hallazgos con los filtros seleccionados.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          {/* Findings list */}
          <Card className="xl:col-span-5">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Lista de Hallazgos</CardTitle>
              <CardDescription>Selecciona un hallazgo para ver mitigación y snippets.</CardDescription>
            </CardHeader>
            <CardContent className="terminal-scroll max-h-[680px] space-y-2 overflow-y-auto pr-2">
              {filtered.map((finding) => {
                const isSelected = selectedFinding?.id === finding.id;
                const sevMeta = SEVERITY_META[finding.severity];
                const statusMeta = FINDING_STATUS_META[finding.status];
                return (
                  <button
                    key={finding.id}
                    type="button"
                    onClick={() => setSelectedId(finding.id)}
                    className={cn(
                      "w-full rounded-lg border p-3 text-left transition-all",
                      isSelected
                        ? "border-sky-500/60 bg-sky-500/10 shadow-md"
                        : "border-slate-800 bg-slate-950/60 hover:border-slate-700 hover:bg-slate-900"
                    )}
                  >
                    <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                          sevMeta.badgeClass
                        )}
                      >
                        {sevMeta.label}
                      </span>
                      <Badge variant="default" className="font-mono text-[10px]">
                        {finding.owasp_category_code}
                      </Badge>
                      <span
                        className={cn(
                          "ml-auto rounded border px-1.5 py-0.5 text-[10px]",
                          statusMeta.badgeClass
                        )}
                      >
                        {statusMeta.label}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-slate-100 line-clamp-2">{finding.title}</p>
                    <p className="mt-1 truncate font-mono text-[11px] text-slate-400">
                      {finding.module_key} {finding.affected_component ? `• ${finding.affected_component}` : ""}
                    </p>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          {/* Finding detail & remediation inspector */}
          <Card className="xl:col-span-7">
            {selectedFinding ? (
              <>
                <CardHeader className="border-b border-slate-800/80 pb-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            "rounded border px-2 py-0.5 text-xs font-semibold uppercase",
                            SEVERITY_META[selectedFinding.severity].badgeClass
                          )}
                        >
                          {SEVERITY_META[selectedFinding.severity].label}
                        </span>
                        <Badge variant="default" className="font-mono">
                          {selectedFinding.owasp_category_code}
                          {selectedFinding.owasp_category_name_es
                            ? ` — ${selectedFinding.owasp_category_name_es}`
                            : ""}
                        </Badge>
                        {selectedFinding.secondary_owasp_codes.map((sec) => (
                          <Badge key={sec} variant="outline" className="font-mono text-[11px]">
                            +{sec}
                          </Badge>
                        ))}
                        {selectedFinding.cwe_id && (
                          <Badge variant="secondary" className="font-mono">
                            {selectedFinding.cwe_id}
                          </Badge>
                        )}
                        {selectedFinding.cvss_score !== null && (
                          <Badge variant="warning" className="font-mono">
                            CVSS {selectedFinding.cvss_score.toFixed(1)}
                          </Badge>
                        )}
                      </div>
                      <CardTitle className="text-lg leading-snug">
                        {selectedFinding.title}
                      </CardTitle>
                      {selectedFinding.affected_component && (
                        <p className="font-mono text-xs text-cyan-300 break-all">
                          Componente afectado: {selectedFinding.affected_component}
                        </p>
                      )}
                    </div>

                    <div className="w-44 shrink-0">
                      <label className="mb-1 block text-[11px] font-medium text-slate-400">
                        Estado de Triaje
                      </label>
                      <Select
                        disabled={updatingId === selectedFinding.id}
                        value={selectedFinding.status}
                        onChange={(e) =>
                          void handleStatusUpdate(
                            selectedFinding.id,
                            e.target.value as FindingStatus
                          )
                        }
                      >
                        <option value="open">Abierto</option>
                        <option value="acknowledged">Reconocido</option>
                        <option value="mitigated">Mitigado</option>
                        <option value="false_positive">Falso Positivo</option>
                      </Select>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-5 pt-4">
                  {/* Technical description */}
                  <section className="space-y-1.5">
                    <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
                      <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                      Descripción Técnica
                    </h4>
                    <p className="text-sm leading-relaxed text-slate-200">
                      {selectedFinding.technical_description}
                    </p>
                  </section>

                  {/* CVEs if present */}
                  {selectedFinding.cve_ids.length > 0 && (
                    <section className="space-y-1.5">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        CVEs Asociados
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {selectedFinding.cve_ids.map((cve) => (
                          <a
                            key={cve}
                            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 rounded-md border border-red-500/40 bg-red-500/10 px-2.5 py-1 font-mono text-xs text-red-300 hover:bg-red-500/20"
                          >
                            {cve}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Remediation steps */}
                  <section className="space-y-2 rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-3.5">
                    <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-300">
                      <Wrench className="h-3.5 w-3.5" />
                      Pasos de Remediación
                    </h4>
                    <p className="text-sm leading-relaxed text-slate-200">
                      {selectedFinding.remediation_steps}
                    </p>
                  </section>

                  {/* Copyable remediation snippets (Nginx / Apache / HTML) */}
                  {Object.keys(selectedFinding.remediation_snippets).length > 0 && (
                    <section className="space-y-2.5">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Snippets de Mitigación
                      </h4>
                      {Object.entries(selectedFinding.remediation_snippets).map(([target, code]) => {
                        const copyId = `${selectedFinding.id}-${target}`;
                        return (
                          <div
                            key={target}
                            className="overflow-hidden rounded-lg border border-slate-800 bg-slate-950"
                          >
                            <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-3 py-1.5">
                              <span className="font-mono text-xs font-semibold uppercase text-sky-300">
                                {target}
                              </span>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-2 text-xs"
                                onClick={() => void copyText(copyId, code)}
                              >
                                {copiedKey === copyId ? (
                                  <>
                                    <Check className="h-3 w-3 text-emerald-400" />
                                    Copiado
                                  </>
                                ) : (
                                  <>
                                    <Copy className="h-3 w-3" />
                                    Copiar
                                  </>
                                )}
                              </Button>
                            </div>
                            <pre className="overflow-x-auto p-3 font-mono text-xs text-slate-200">
                              {code}
                            </pre>
                          </div>
                        );
                      })}
                    </section>
                  )}

                  {/* Evidence */}
                  {Object.keys(selectedFinding.evidence).length > 0 && (
                    <section className="space-y-1.5">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Evidencia Estructurada
                      </h4>
                      <pre className="terminal-scroll max-h-56 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
                        {JSON.stringify(selectedFinding.evidence, null, 2)}
                      </pre>
                    </section>
                  )}

                  {/* References */}
                  {selectedFinding.references.length > 0 && (
                    <section className="space-y-1">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Referencias
                      </h4>
                      <div className="flex flex-col gap-1">
                        {selectedFinding.references.map((ref) => (
                          <a
                            key={ref}
                            href={ref}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline break-all"
                          >
                            {ref}
                            <ExternalLink className="h-3 w-3 shrink-0" />
                          </a>
                        ))}
                      </div>
                    </section>
                  )}
                </CardContent>
              </>
            ) : null}
          </Card>
        </div>
      )}
    </div>
  );
}
