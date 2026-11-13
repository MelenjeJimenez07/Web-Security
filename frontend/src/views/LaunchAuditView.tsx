import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Play, ShieldAlert, ShieldCheck } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select, Textarea } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { ApiError, api } from "@/services/api";
import type { Asset, ScanProfile, ScannerInfo } from "@/types/api";

interface LaunchAuditViewProps {
  assets: Asset[];
  scanners: ScannerInfo[];
  preselectedAssetId?: string | null;
  onGoToAssets: () => void;
  onAuditLaunched: (auditId: string) => void;
}

export function LaunchAuditView({
  assets,
  scanners,
  preselectedAssetId,
  onGoToAssets,
  onAuditLaunched,
}: LaunchAuditViewProps) {
  const [assetId, setAssetId] = useState<string>(preselectedAssetId || assets[0]?.id || "");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("quick");
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [requestedBy, setRequestedBy] = useState<string>("appsec-architect");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState<boolean>(false);
  const [authorizationStatement, setAuthorizationStatement] = useState<string>(
    "Confirmo que poseo autorización expresa y por escrito del propietario del activo para ejecutar estas pruebas de seguridad."
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (preselectedAssetId) {
      setAssetId(preselectedAssetId);
    } else if (!assetId && assets.length > 0) {
      setAssetId(assets[0].id);
    }
  }, [preselectedAssetId, assets, assetId]);

  useEffect(() => {
    if (selectedModules.length === 0 && scanners.length > 0) {
      setSelectedModules(scanners.map((s) => s.module_key));
    }
  }, [scanners, selectedModules.length]);

  const currentAsset = assets.find((a) => a.id === assetId) ?? null;
  const activeModuleSelected = selectedModules.some((key) =>
    scanners.find((s) => s.module_key === key)?.is_active
  );
  const requiresVerificationWarning = Boolean(
    currentAsset && !currentAsset.is_verified && activeModuleSelected
  );

  const toggleModule = (key: string) => {
    setSelectedModules((prev) =>
      prev.includes(key) ? prev.filter((item) => item !== key) : [...prev, key]
    );
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!assetId) {
      setError("Debes seleccionar un activo registrado.");
      return;
    }
    if (selectedModules.length === 0) {
      setError("Selecciona al menos un módulo de auditoría.");
      return;
    }
    if (!authorizationConfirmed) {
      setError("La confirmación explícita de autorización es obligatoria.");
      return;
    }

    setSubmitting(true);
    try {
      const created = await api.launchAudit({
        asset_id: assetId,
        scan_profile: scanProfile,
        selected_modules: selectedModules,
        authorization_confirmed: authorizationConfirmed,
        authorization_statement: authorizationStatement,
        requested_by: requestedBy,
      });
      onAuditLaunched(created.id);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Error inesperado al encolar la auditoría.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Lanzamiento de Auditoría de Seguridad
        </h1>
        <p className="text-sm text-slate-400">
          Configura el perfil de escaneo, selecciona los módulos OWASP Top 10:2025 y registra la autorización formal.
        </p>
      </div>

      {assets.length === 0 ? (
        <Alert variant="warning" className="flex flex-wrap items-center justify-between gap-3">
          <span>No hay activos registrados todavía. Registra un dominio, URL o IP pública primero.</span>
          <Button size="sm" onClick={onGoToAssets}>
            Ir a Activos y Verificación
          </Button>
        </Alert>
      ) : (
        <form onSubmit={handleLaunch} className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-6 xl:col-span-7">
            {/* Target & Profile */}
            <Card>
              <CardHeader>
                <CardTitle>1. Objetivo y Perfil de Red</CardTitle>
                <CardDescription>
                  Selecciona el activo autorizado y el perfil de reconocimiento Nmap.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Activo Objetivo</label>
                  <Select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
                    {assets.map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.name} ({asset.normalized_target}) —{" "}
                        {asset.is_verified ? "Verificado" : "Sin verificar"}
                      </option>
                    ))}
                  </Select>
                </div>

                {currentAsset && (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs">
                    <span className="font-mono text-slate-300">
                      IP validada: {currentAsset.resolved_ip || "Pendiente"}
                    </span>
                    {currentAsset.is_verified ? (
                      <Badge variant="success">
                        <CheckCircle2 className="h-3 w-3" />
                        Propiedad Verificada
                      </Badge>
                    ) : (
                      <Badge variant="warning">
                        <ShieldAlert className="h-3 w-3" />
                        Sin Verificación de Propiedad
                      </Badge>
                    )}
                  </div>
                )}

                {requiresVerificationWarning && (
                  <Alert variant="warning" className="space-y-2">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                      <div className="text-xs leading-relaxed">
                        Este activo aún no completó la verificación de propiedad (DNS TXT o{" "}
                        <code>.well-known/security-audit.txt</code>). Si el backend tiene{" "}
                        <code>REQUIRE_DOMAIN_VERIFICATION=true</code>, los módulos activos serán bloqueados o puedes ejecutar únicamente el módulo pasivo{" "}
                        <strong>dns_passive</strong>.
                      </div>
                    </div>
                    <Button size="sm" variant="outline" onClick={onGoToAssets}>
                      Verificar Propiedad del Activo
                    </Button>
                  </Alert>
                )}

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">
                    Perfil de Escaneo Nmap
                  </label>
                  <Select
                    value={scanProfile}
                    onChange={(e) => setScanProfile(e.target.value as ScanProfile)}
                  >
                    <option value="quick">Rápido (Top 100 puertos TCP - -sT -T4)</option>
                    <option value="top_1000">Estándar (Top 1000 puertos TCP)</option>
                    <option value="service_version">
                      Detección de Servicios y Versiones (Top 1000 + -sV)
                    </option>
                  </Select>
                </div>
              </CardContent>
            </Card>

            {/* Modules Selector */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle>2. Módulos de Auditoría (Plugins)</CardTitle>
                  <CardDescription>
                    Todos los hallazgos se etiquetan automáticamente contra OWASP Top 10:2025.
                  </CardDescription>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setSelectedModules(scanners.map((s) => s.module_key))}
                >
                  Seleccionar todos
                </Button>
              </CardHeader>
              <CardContent className="space-y-2.5">
                {scanners.map((mod) => {
                  const checked = selectedModules.includes(mod.module_key);
                  return (
                    <label
                      key={mod.module_key}
                      className={cn(
                        "flex cursor-pointer items-start gap-3 rounded-lg border p-3.5 transition-colors",
                        checked
                          ? "border-sky-500/50 bg-sky-500/10"
                          : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                      )}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleModule(mod.module_key)}
                        className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900 text-sky-500 focus:ring-sky-500"
                      />
                      <div className="flex-1 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-semibold text-slate-100">
                            {mod.module_name}
                          </span>
                          <Badge variant={mod.is_active ? "warning" : "success"}>
                            {mod.is_active ? "Activo" : "Pasivo"}
                          </Badge>
                        </div>
                        <p className="text-xs text-slate-400">{mod.description}</p>
                        <div className="flex flex-wrap gap-1 pt-0.5">
                          {mod.default_owasp_categories.map((code) => (
                            <Badge key={code} variant="default" className="font-mono text-[10px]">
                              {code}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          {/* Governance & Authorization Gate */}
          <div className="xl:col-span-5">
            <Card className="sticky top-6 border-sky-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-sky-400" />
                  3. Autorización Ética y Gobernanza
                </CardTitle>
                <CardDescription>
                  Registro obligatorio en la bitácora inmutable (OWASP A09:2025) antes de encolar en Celery.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {error && <Alert variant="destructive">{error}</Alert>}

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">
                    Auditor / Operador Responsable
                  </label>
                  <Input
                    required
                    value={requestedBy}
                    onChange={(e) => setRequestedBy(e.target.value)}
                    placeholder="nombre.auditor"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">
                    Declaración de Autorización
                  </label>
                  <Textarea
                    required
                    value={authorizationStatement}
                    onChange={(e) => setAuthorizationStatement(e.target.value)}
                    rows={3}
                  />
                </div>

                <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5">
                  <input
                    type="checkbox"
                    checked={authorizationConfirmed}
                    onChange={(e) => setAuthorizationConfirmed(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-amber-400 text-sky-500"
                  />
                  <span className="text-xs leading-relaxed text-amber-100">
                    Confirmo explícitamente que cuento con autorización legítima para auditar este activo y asumo la responsabilidad operativa del análisis.
                  </span>
                </label>

                <Button
                  type="submit"
                  size="lg"
                  className="w-full"
                  disabled={submitting || !authorizationConfirmed || selectedModules.length === 0}
                >
                  <Play className="h-4 w-4" />
                  {submitting ? "Encolando en Celery..." : "Ejecutar Auditoría Ahora"}
                </Button>
              </CardContent>
            </Card>
          </div>
        </form>
      )}
    </div>
  );
}
