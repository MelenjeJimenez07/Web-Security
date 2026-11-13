import {
  Activity,
  BookOpen,
  FileSearch,
  GlobeLock,
  LayoutDashboard,
  Play,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type NavSection =
  | "overview"
  | "assets"
  | "launch"
  | "audits"
  | "owasp"
  | "logs";

interface SidebarProps {
  activeSection: NavSection;
  onSelect: (section: NavSection) => void;
  activeAuditsCount: number;
}

const NAV_ITEMS: Array<{
  id: NavSection;
  label: string;
  icon: typeof LayoutDashboard;
}> = [
  { id: "overview", label: "Resumen & Métricas", icon: LayoutDashboard },
  { id: "assets", label: "Activos & Verificación", icon: GlobeLock },
  { id: "launch", label: "Lanzar Auditoría", icon: Play },
  { id: "audits", label: "Auditorías & Hallazgos", icon: FileSearch },
  { id: "owasp", label: "OWASP Top 10:2025", icon: BookOpen },
  { id: "logs", label: "Bitácora A09:2025", icon: Activity },
];

export function Sidebar({ activeSection, onSelect, activeAuditsCount }: SidebarProps) {
  return (
    <aside className="flex w-full flex-col border-b border-slate-800 bg-slate-950/90 lg:min-h-screen lg:w-64 lg:border-b-0 lg:border-r">
      <div className="flex items-center gap-3 border-b border-slate-800/80 px-5 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/15 text-sky-400 ring-1 ring-sky-500/30">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <p className="text-sm font-bold tracking-tight text-slate-100">WebSec Audit</p>
          <p className="text-[11px] font-medium text-sky-400">OWASP Top 10:2025</p>
        </div>
      </div>

      <nav className="flex flex-row gap-1 overflow-x-auto p-3 lg:flex-col">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = activeSection === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelect(item.id)}
              className={cn(
                "flex shrink-0 items-center justify-between gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors",
                active
                  ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-100"
              )}
            >
              <span className="flex items-center gap-2.5">
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </span>
              {item.id === "audits" && activeAuditsCount > 0 && (
                <span className="rounded-full bg-indigo-500/25 px-2 py-0.5 text-[11px] font-semibold text-indigo-300">
                  {activeAuditsCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-auto hidden border-t border-slate-800/80 p-4 lg:block">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
          <p className="font-semibold text-slate-200">Controles Activos</p>
          <p className="mt-1 leading-relaxed">
            Anti-SSRF estricto, ejecución sin shell y verificación obligatoria de autorización.
          </p>
        </div>
      </div>
    </aside>
  );
}
