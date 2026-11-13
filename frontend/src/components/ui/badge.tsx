import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-sky-500/40 bg-sky-500/15 text-sky-300",
        secondary: "border-slate-700 bg-slate-800 text-slate-300",
        success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
        warning: "border-amber-500/40 bg-amber-500/15 text-amber-300",
        destructive: "border-red-500/40 bg-red-500/15 text-red-400",
        outline: "border-slate-700 text-slate-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
