import { useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  GlobeLock,
  KeyRound,
  Play,
  Plus,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select, Textarea } from "@/components/ui/input";
import { formatDateTime } from "@/lib/utils";
import { ApiError, api } from "@/services/api";
import type { Asset, AssetDetail, VerificationMethod } from "@/types/api";

interface AssetsVerificationViewProps {
  assets: Asset[];
  onRefreshAssets: () => Promise<void>;
  onLaunchForAsset: (assetId: string) => void;
}

function findDuplicateAsset(assets: Asset[], errorMessage: string): Asset | null {
  const quotedTarget = errorMessage.match(/'([^']+)'/)?.[1]?.toLowerCase();
  if (quotedTarget) {
    const exact = assets.find((asset) => asset.normalized_target.toLowerCase() === quotedTarget);
    if (exact) return exact;
  }
  const lowered = errorMessage.toLowerCase();
  return assets.find((asset) => lowered.includes(asset.normalized_target.toLowerCase())) ?? null;
}

export function AssetsVerificationView({
  assets,
  onRefreshAssets,
  onLaunchForAsset,
}: AssetsVerificationViewProps) {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [environment, setEnvironment] = useState("production");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [notes, setNotes] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  const [duplicateAsset, setDuplicateAsset] = useState<Asset | null>(null);

  const [selectedAsset, setSelectedAsset] = useState<AssetDetail | null>(null);
  const [verifMethod, setVerifMethod] = useState<VerificationMethod>("dns_txt");
  const [verifLoading, setVerifLoading] = useState(false);
  const [verifMessage, setVerifMessage] = useState<{ type: "info" | "success" | "destructive"; text: string } | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    setDuplicateAsset(null);
    setCreating(true);
    try {
      const created = await api.createAsset({
        name,
        target,
        environment,
        owner_email: ownerEmail || undefined,
        notes: notes || undefined,
      });
      setName("");
      setTarget("");
      setOwnerEmail("");
      setNotes("");
      setFormSuccess(
        `Activo '${created.normalized_target}' registrado (IP resuelta: ${created.resolved_ip || "N/A"}).`
      );
      await onRefreshAssets();
      const detail = await api.getAsset(created.id);
      setSelectedAsset(detail);
      setVerifMethod(detail.target_type === "ip" ? "well_known_file" : "dns_txt");
    } catch (err) {
      if (err instanceof ApiError) {
        setFormError(err.message);
        setDuplicateAsset(err.status === 409 ? findDuplicateAsset(assets, err.message) : null);
      } else {
        setFormError("No se pudo registrar el activo.");
        setDuplicateAsset(null);
      }
    } finally {
      setCreating(false);
    }
  };

  const openVerificationPanel = async (assetId: string) => {
    setVerifMessage(null);
    try {
      const detail = await api.getAsset(assetId);
      setSelectedAsset(detail);
      setVerifMethod(detail.target_type === "ip" ? "well_known_file" : "dns_txt");
    } catch (err) {
      setVerifMessage({
        type: "destructive",
        text: err instanceof ApiError ? err.message : "Error cargando detalle del activo.",
      });
    }
  };

  const handleGenerateChallenge = async () => {
    if (!selectedAsset) return;
    setVerifLoading(true);
    setVerifMessage(null);
    try {
      await api.createVerificationChallenge(selectedAsset.id, verifMethod);
      const updated = await api.getAsset(selectedAsset.id);
      setSelectedAsset(updated);
      setVerifMessage({
        type: "info",
        text: "Reto generado. Publica el token indicado y presiona 'Verificar Propiedad Ahora'.",
      });
    } catch (err) {
      setVerifMessage({
        type: "destructive",
        text: err instanceof ApiError ? err.message : "Error generando reto de verificación.",
      });
    } finally {
      setVerifLoading(false);
    }
  };

  const handleCheckChallenge = async (verificationId: string) => {
    if (!selectedAsset) return;
    setVerifLoading(true);
    setVerifMessage(null);
    try {
      const res = await api.checkVerificationChallenge(selectedAsset.id, verificationId);
      const updated = await api.getAsset(selectedAsset.id);
      setSelectedAsset(updated);
      await onRefreshAssets();
      setVerifMessage({
        type: res.verified ? "success" : "destructive",
        text: res.message,
      });
    } catch (err) {
      setVerifMessage({
        type: "destructive",
        text: err instanceof ApiError ? err.message : "Error validando reto de propiedad.",
      });
    } finally {
      setVerifLoading(false);
    }
  };

  const handleDeleteAsset = async (assetId: string) => {
    setFormError(null);
    try {
      await api.deleteAsset(assetId);
      if (selectedAsset?.id === assetId) {
        setSelectedAsset(null);
      }
      await onRefreshAssets();
    } catch (err) {
      setFormError(
        err instanceof ApiError ? err.message : "No se pudo eliminar el activo."
      );
    }
  };

  const copyToken = async (token: string) => {
    try {
      await navigator.clipboard.writeText(token);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 1800);
    } catch {
      // Ignore clipboard failure
    }
  };

  const latestChallenge = selectedAsset?.verifications[0] ?? null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Activos y Verificación de Propiedad
        </h1>
        <p className="text-sm text-slate-400">
          Registra dominios, URLs o IPs públicas (con protección anti-SSRF) y verifica propiedad antes de ejecutar módulos activos.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Create Asset Form */}
        <Card className="xl:col-span-5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Plus className="h-4 w-4 text-sky-400" />
              Registrar Nuevo Activo
            </CardTitle>
            <CardDescription>
              El sistema resuelve el objetivo y bloquea automáticamente IPs privadas, loopback o metadata (A01:2025 SSRF).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreateAsset} className="space-y-4">
              {formError && (
                <Alert variant="destructive">
                  <div className="space-y-2">
                    <p>{formError}</p>
                    {duplicateAsset &&
                      (duplicateAsset.is_verified ? (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => onLaunchForAsset(duplicateAsset.id)}
                        >
                          Volver a auditar activo existente
                        </Button>
                      ) : (
                        <p className="text-xs text-red-200/90">
                          Activo registrado ({duplicateAsset.name}) pendiente de verificación en la tabla de inventario.
                        </p>
                      ))}
                  </div>
                </Alert>
              )}
              {formSuccess && <Alert variant="success">{formSuccess}</Alert>}

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Nombre descriptivo</label>
                <Input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Ej. Portal Corporativo Producción"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Objetivo (Dominio, URL HTTPS/HTTP o IP pública)
                </label>
                <Input
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://app.ejemplo.com o ejemplo.com"
                  className="font-mono"
                />
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Entorno</label>
                  <Select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                    <option value="production">Producción</option>
                    <option value="staging">Staging / Pre-Prod</option>
                    <option value="lab">Laboratorio Autorizado</option>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Contacto Técnico</label>
                  <Input
                    type="email"
                    value={ownerEmail}
                    onChange={(e) => setOwnerEmail(e.target.value)}
                    placeholder="secops@ejemplo.com"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Notas de alcance</label>
                <Textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Ventana de mantenimiento autorizada, responsable, alcance..."
                />
              </div>

              <Button type="submit" disabled={creating} className="w-full">
                {creating ? "Validando objetivo..." : "Registrar y Validar Anti-SSRF"}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Verification Wizard */}
        <Card className="xl:col-span-7">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-emerald-400" />
              Verificación de Propiedad del Dominio
            </CardTitle>
            <CardDescription>
              Requerida antes de ejecutar escaneos activos mediante registro DNS TXT o archivo{" "}
              <code className="text-sky-300">.well-known/security-audit.txt</code>.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!selectedAsset ? (
              <div className="flex h-64 flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 p-6 text-center text-sm text-slate-400">
                <GlobeLock className="mb-2 h-8 w-8 text-slate-600" />
                Selecciona un activo en el inventario inferior para gestionar su verificación de propiedad.
              </div>
            ) : (
              <>
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3.5">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">{selectedAsset.name}</p>
                    <p className="font-mono text-xs text-slate-400">
                      {selectedAsset.normalized_target} • IP: {selectedAsset.resolved_ip || "N/A"}
                    </p>
                  </div>
                  {selectedAsset.is_verified ? (
                    <Badge variant="success">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Propiedad Verificada ({selectedAsset.verification_method})
                    </Badge>
                  ) : (
                    <Badge variant="warning">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Verificación Pendiente
                    </Badge>
                  )}
                </div>

                {verifMessage && <Alert variant={verifMessage.type}>{verifMessage.text}</Alert>}

                <div className="flex flex-wrap items-end gap-3">
                  <div className="min-w-[240px] flex-1 space-y-1.5">
                    <label className="text-xs font-medium text-slate-300">Método de verificación</label>
                    <Select
                      value={verifMethod}
                      onChange={(e) => setVerifMethod(e.target.value as VerificationMethod)}
                    >
                      <option value="dns_txt" disabled={selectedAsset.target_type === "ip"}>
                        Registro DNS TXT (_websec-audit.{selectedAsset.hostname})
                      </option>
                      <option value="well_known_file">
                        Archivo Web (/.well-known/security-audit.txt)
                      </option>
                    </Select>
                  </div>
                  <Button onClick={handleGenerateChallenge} disabled={verifLoading}>
                    Generar Reto de Verificación
                  </Button>
                </div>

                {latestChallenge && (
                  <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-950/80 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-semibold uppercase tracking-wider text-sky-300">
                        Último Reto ({latestChallenge.method})
                      </span>
                      <Badge
                        variant={
                          latestChallenge.status === "verified"
                            ? "success"
                            : latestChallenge.status === "failed"
                              ? "destructive"
                              : "warning"
                        }
                      >
                        {latestChallenge.status}
                      </Badge>
                    </div>

                    <p className="text-xs text-slate-300">{latestChallenge.instructions}</p>

                    <div className="flex items-center justify-between gap-2 rounded-md border border-slate-800 bg-slate-900 px-3 py-2">
                      <code className="truncate font-mono text-xs text-emerald-300">
                        {latestChallenge.challenge_token}
                      </code>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => void copyToken(latestChallenge.challenge_token)}
                      >
                        {copiedToken ? (
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <span className="text-[11px] text-slate-500">
                        Expira: {formatDateTime(latestChallenge.expires_at)}
                      </span>
                      <Button
                        size="sm"
                        variant="default"
                        disabled={verifLoading}
                        onClick={() => void handleCheckChallenge(latestChallenge.id)}
                      >
                        {verifLoading ? "Consultando..." : "Verificar Propiedad Ahora"}
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Assets Inventory Table */}
      <Card>
        <CardHeader>
          <CardTitle>Inventario de Activos ({assets.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {assets.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-500">
              No hay activos registrados todavía.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-800 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="py-2.5 pr-4">Nombre</th>
                    <th className="py-2.5 pr-4">Objetivo Normalizado</th>
                    <th className="py-2.5 pr-4">IP Resuelta</th>
                    <th className="py-2.5 pr-4">Entorno</th>
                    <th className="py-2.5 pr-4">Propiedad</th>
                    <th className="py-2.5 text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {assets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-slate-800/30">
                      <td className="py-3 pr-4 font-medium text-slate-100">{asset.name}</td>
                      <td className="py-3 pr-4 font-mono text-xs text-sky-300">
                        {asset.normalized_target}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-slate-400">
                        {asset.resolved_ip || "—"}
                      </td>
                      <td className="py-3 pr-4">
                        <Badge variant="secondary">{asset.environment}</Badge>
                      </td>
                      <td className="py-3 pr-4">
                        {asset.is_verified ? (
                          <Badge variant="success">Verificado</Badge>
                        ) : (
                          <Badge variant="warning">Sin verificar</Badge>
                        )}
                      </td>
                      <td className="py-3 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void openVerificationPanel(asset.id)}
                          >
                            Verificar
                          </Button>
                          <Button
                            size="sm"
                            variant="default"
                            onClick={() => onLaunchForAsset(asset.id)}
                          >
                            <Play className="h-3 w-3" />
                            Auditar
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void handleDeleteAsset(asset.id)}
                            title="Eliminar activo"
                          >
                            <Trash2 className="h-3.5 w-3.5 text-red-400" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
