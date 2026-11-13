import { cn } from "@/lib/utils";

interface ProgressProps {
  value: number;
  className?: string;
}

export function Progress({ value, className }: ProgressProps) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
      className={cn("h-2.5 w-full overflow-hidden rounded-full bg-slate-800", className)}
    >
      <div
        className="h-full rounded-full bg-gradient-to-r from-sky-500 to-cyan-400 transition-all duration-300"
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}
