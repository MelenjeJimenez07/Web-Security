import { useEffect, useRef, useState } from "react";
import { Radio, RefreshCw, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn, isTerminalAuditStatus } from "@/lib/utils";
import { api } from "@/services/api";
import type { AuditStatus, StreamLogEvent } from "@/types/api";

interface LiveAuditConsoleProps {
  auditId: string;
  initialStatus: AuditStatus;
  initialProgress: number;
  initialStage: string | null;
  onStatusUpdate?: () => void;
}

type ConnectionMode = "connecting" | "websocket" | "sse" | "closed";

export function LiveAuditConsole({
  auditId,
  initialStatus,
  initialProgress,
  initialStage,
  onStatusUpdate,
}: LiveAuditConsoleProps) {
  const [logs, setLogs] = useState<StreamLogEvent[]>([]);
  const [mode, setMode] = useState<ConnectionMode>("connecting");
  const [progress, setProgress] = useState<number>(initialProgress);
  const [stage, setStage] = useState<string>(initialStage || "Esperando eventos...");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const [reconnectTick, setReconnectTick] = useState<number>(0);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const onStatusUpdateRef = useRef(onStatusUpdate);
  onStatusUpdateRef.current = onStatusUpdate;

  useEffect(() => {
    setProgress(initialProgress);
    if (initialStage) {
      setStage(initialStage);
    }
  }, [initialProgress, initialStage]);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;
    let sse: EventSource | null = null;
    const seen = new Set<string>();

    const appendEvent = (evt: StreamLogEvent) => {
      if (evt.event_type === "HEARTBEAT") return;
      const dedupeKey = `${evt.timestamp || ""}|${evt.event_type}|${evt.message || ""}`;
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);

      setLogs((prev) => [...prev, evt]);
      if (typeof evt.progress_percent === "number") {
        setProgress(evt.progress_percent);
      }
      if (evt.module_key && evt.event_type === "MODULE_STARTED") {
        setStage(`Módulo activo: ${evt.module_key}`);
      } else if (evt.message && (evt.event_type === "AUDIT_COMPLETED" || evt.event_type === "AUDIT_FAILED")) {
        setStage(evt.event_type === "AUDIT_COMPLETED" ? "Auditoría finalizada" : "Auditoría fallida");
      }

      if (
        evt.event_type === "MODULE_COMPLETED" ||
        evt.event_type === "MODULE_FAILED" ||
        evt.event_type === "AUDIT_COMPLETED" ||
        evt.event_type === "AUDIT_FAILED" ||
        evt.event_type === "STREAM_EOF"
      ) {
        onStatusUpdateRef.current?.();
      }
    };

    const startSseFallback = () => {
      if (disposed) return;
      setMode("sse");
      sse = new EventSource(api.buildAuditSseUrl(auditId));
      sse.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as StreamLogEvent;
          appendEvent(parsed);
          if (parsed.event_type === "AUDIT_COMPLETED" || parsed.event_type === "AUDIT_FAILED") {
            sse?.close();
            setMode("closed");
          }
        } catch {
          // Ignore malformed keepalive chunks
        }
      };
      sse.onerror = () => {
        sse?.close();
        setMode("closed");
      };
    };

    const connect = async () => {
      setLogs([]);
      setMode("connecting");

      try {
        const snapshot = await api.getAuditLogs(auditId);
        if (disposed) return;
        for (const item of snapshot.stream_logs) {
          appendEvent(item);
        }
      } catch {
        // Proceed directly to stream connection
      }

      if (disposed) return;
      if (isTerminalAuditStatus(initialStatus)) {
        setMode("closed");
        return;
      }

      let wsConnected = false;
      try {
        ws = new WebSocket(api.buildAuditWebSocketUrl(auditId));
        ws.onopen = () => {
          wsConnected = true;
          if (!disposed) setMode("websocket");
        };
        ws.onmessage = (msg) => {
          try {
            const parsed = JSON.parse(msg.data as string) as StreamLogEvent;
            appendEvent(parsed);
            if (
              parsed.event_type === "AUDIT_COMPLETED" ||
              parsed.event_type === "AUDIT_FAILED" ||
              parsed.event_type === "STREAM_EOF"
            ) {
              setMode("closed");
            }
          } catch {
            // Ignore plain ping frames
          }
        };
        ws.onerror = () => {
          if (!wsConnected && !disposed) {
            ws?.close();
            startSseFallback();
          }
        };
        ws.onclose = () => {
          if (!disposed && !wsConnected) {
            startSseFallback();
          } else if (!disposed) {
            setMode("closed");
          }
        };
      } catch {
        startSseFallback();
      }
    };

    void connect();

    return () => {
      disposed = true;
      ws?.close();
      sse?.close();
    };
  }, [auditId, initialStatus, reconnectTick]);

  const filteredLogs = logs.filter((entry) => {
    if (levelFilter === "all") return true;
    return (entry.level || "info").toLowerCase() === levelFilter;
  });

  const modeBadge = () => {
    switch (mode) {
      case "websocket":
        return (
          <Badge variant="success">
            <Radio className="h-3 w-3 animate-pulse" />
            WebSocket En Vivo
          </Badge>
        );
      case "sse":
        return (
          <Badge variant="default">
            <Radio className="h-3 w-3 animate-pulse" />
            SSE En Vivo
          </Badge>
        );
      case "connecting":
        return <Badge variant="warning">Conectando stream...</Badge>;
      case "closed":
        return <Badge variant="secondary">Stream finalizado</Badge>;
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-sky-400" />
            Consola de Ejecución en Tiempo Real
          </CardTitle>
          <CardDescription>{stage}</CardDescription>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {modeBadge()}
          <select
            aria-label="Filtrar nivel de log"
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="h-8 rounded-md border border-slate-700 bg-slate-950 px-2 text-xs text-slate-200"
          >
            <option value="all">Todos los niveles</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
          </select>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setAutoScroll((prev) => !prev)}
          >
            {autoScroll ? "Auto-scroll: ON" : "Auto-scroll: OFF"}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setReconnectTick((t) => t + 1)}
            title="Reconectar stream"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Progreso global del escaneo</span>
            <span className="font-mono font-semibold text-sky-300">{progress}%</span>
          </div>
          <Progress value={progress} />
        </div>

        <div
          ref={containerRef}
          className="terminal-scroll h-72 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs leading-relaxed"
        >
          {filteredLogs.length === 0 ? (
            <p className="text-slate-500">
              Esperando telemetría del worker Celery...
            </p>
          ) : (
            filteredLogs.map((entry, idx) => {
              const lvl = (entry.level || "info").toLowerCase();
              const timeLabel = entry.timestamp
                ? new Date(entry.timestamp).toLocaleTimeString("es-ES", { hour12: false })
                : "--:--:--";
              return (
                <div
                  key={`${entry.timestamp || idx}-${idx}`}
                  className="flex items-start gap-2 border-b border-slate-900/80 py-1 last:border-b-0"
                >
                  <span className="shrink-0 text-slate-500">[{timeLabel}]</span>
                  <span
                    className={cn(
                      "w-14 shrink-0 uppercase font-semibold",
                      lvl === "error"
                        ? "text-red-400"
                        : lvl === "warning"
                          ? "text-amber-300"
                          : "text-sky-400"
                    )}
                  >
                    {lvl}
                  </span>
                  {entry.module_key && (
                    <span className="shrink-0 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-cyan-300">
                      {entry.module_key}
                    </span>
                  )}
                  <span className="text-slate-200 break-words">{entry.message}</span>
                </div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}
