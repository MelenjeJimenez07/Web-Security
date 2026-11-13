import { cn } from "@/lib/utils";

export interface TabOption {
  id: string;
  label: string;
  badge?: string | number;
}

interface TabsBarProps {
  tabs: TabOption[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
}

export function TabsBar({ tabs, activeTab, onChange, className }: TabsBarProps) {
  return (
    <div
      className={cn(
        "inline-flex flex-wrap items-center gap-1 rounded-lg border border-slate-800 bg-slate-950/70 p-1",
        className
      )}
    >
      {tabs.map((tab) => {
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={cn(
              "inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              active
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/30"
                : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"
            )}
          >
            <span>{tab.label}</span>
            {tab.badge !== undefined && (
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 text-[10px]",
                  active ? "bg-sky-500/30 text-sky-200" : "bg-slate-800 text-slate-400"
                )}
              >
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
