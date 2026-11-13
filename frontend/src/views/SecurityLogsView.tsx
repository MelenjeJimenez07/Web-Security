import { RefreshCw, Shield } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDateTime } from "@/lib/utils";
import type { SecurityEventLog } from "@/types/api";

interface SecurityLogsViewProps {
  logs: SecurityEventLog[];
  onRefresh: () => void;
}

export function SecurityLogsView({ logs, onRefresh }: SecurityLogsViewProps) {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Bitácora de Eventos de Seguridad (A09:2025)
          </h1>
          <p className="text-sm text-slate-400">
            Registro estructurado e inmutable de autorizaciones, bloqueos anti-SSRF, verificaciones y cambios de estado.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          <RefreshCw className="h-3.5 w-3.5" />
          Actualizar
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="h-4 w-4 text-sky-400" />
            Eventos Auditados ({logs.length})
          </CardTitle>
          <CardDescription>Últimos 100 eventos registrados por la plataforma.</CardDescription>
        </CardHeader>
        <CardContent>
          {logs.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-500">
              No hay eventos de seguridad registrados todavía.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 uppercase text-slate-400">
                  <tr>
                    <th className="py-2.5 pr-4">Fecha</th>
                    <th className="py-2.5 pr-4">Evento</th>
                    <th className="py-2.5 pr-4">Severidad</th>
                    <th className="py-2.5 pr-4">Actor / IP</th>
                    <th className="py-2.5">Mensaje</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {logs.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/30">
                      <td className="whitespace-nowrap py-2.5 pr-4 font-mono text-slate-400">
                        {formatDateTime(entry.created_at)}
                      </td>
                      <td className="py-2.5 pr-4">
                        <Badge variant="default" className="font-mono text-[10px]">
                          {entry.event_type}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-4">
                        <Badge
                          variant={
                            entry.severity === "critical" || entry.severity === "error"
                              ? "destructive"
                              : entry.severity === "warning"
                                ? "warning"
                                : "secondary"
                          }
                        >
                          {entry.severity}
                        </Badge>
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-slate-400">
                        {entry.actor || "system"} {entry.source_ip ? `(${entry.source_ip})` : ""}
                      </td>
                      <td className="py-2.5 text-slate-200">{entry.message}</td>
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
