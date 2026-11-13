import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { AuditStatus, FindingStatus, SeverityLevel } from "@/types/api";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_META: Record<
  SeverityLevel,
  { label: string; color: string; badgeClass: string; order: number }
> = {
  critical: {
    label: "Crítico",
    color: "#ef4444",
    badgeClass: "bg-red-500/15 text-red-400 border-red-500/40",
    order: 1,
  },
  high: {
    label: "Alto",
    color: "#f97316",
    badgeClass: "bg-orange-500/15 text-orange-400 border-orange-500/40",
    order: 2,
  },
  medium: {
    label: "Medio",
    color: "#eab308",
    badgeClass: "bg-amber-500/15 text-amber-300 border-amber-500/40",
    order: 3,
  },
  low: {
    label: "Bajo",
    color: "#06b6d4",
    badgeClass: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
    order: 4,
  },
  info: {
    label: "Informativo",
    color: "#64748b",
    badgeClass: "bg-slate-500/15 text-slate-300 border-slate-500/40",
    order: 5,
  },
};

export const AUDIT_STATUS_META: Record<
  AuditStatus,
  { label: string; badgeClass: string }
> = {
  pending: { label: "Pendiente", badgeClass: "bg-slate-500/15 text-slate-300 border-slate-500/30" },
  queued: { label: "En Cola", badgeClass: "bg-sky-500/15 text-sky-300 border-sky-500/30" },
  running: { label: "Ejecutando", badgeClass: "bg-indigo-500/20 text-indigo-300 border-indigo-400/40" },
  completed: { label: "Completada", badgeClass: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" },
  partial_failure: { label: "Parcial", badgeClass: "bg-amber-500/15 text-amber-300 border-amber-500/40" },
  failed: { label: "Fallida", badgeClass: "bg-red-500/15 text-red-400 border-red-500/40" },
  cancelled: { label: "Cancelada", badgeClass: "bg-slate-600/20 text-slate-400 border-slate-600/40" },
};

export const FINDING_STATUS_META: Record<
  FindingStatus,
  { label: string; badgeClass: string }
> = {
  open: { label: "Abierto", badgeClass: "bg-red-500/10 text-red-300 border-red-500/30" },
  acknowledged: { label: "Reconocido", badgeClass: "bg-amber-500/10 text-amber-300 border-amber-500/30" },
  mitigated: { label: "Mitigado", badgeClass: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30" },
  false_positive: { label: "Falso Positivo", badgeClass: "bg-slate-500/15 text-slate-300 border-slate-500/30" },
};

export function gradeBadgeClass(grade: string | null | undefined): string {
  switch (grade) {
    case "A+":
    case "A":
      return "bg-emerald-500/20 text-emerald-300 border-emerald-500/50";
    case "B":
      return "bg-sky-500/20 text-sky-300 border-sky-500/50";
    case "C":
      return "bg-amber-500/20 text-amber-300 border-amber-500/50";
    case "D":
      return "bg-orange-500/20 text-orange-300 border-orange-500/50";
    case "F":
      return "bg-red-500/20 text-red-400 border-red-500/50";
    default:
      return "bg-slate-500/20 text-slate-300 border-slate-500/40";
  }
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat("es-ES", {
      dateStyle: "short",
      timeStyle: "medium",
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

export function isTerminalAuditStatus(status: AuditStatus): boolean {
  return (
    status === "completed" ||
    status === "partial_failure" ||
    status === "failed" ||
    status === "cancelled"
  );
}
