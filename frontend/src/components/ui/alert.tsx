import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const alertVariants = cva("relative w-full rounded-lg border px-4 py-3 text-sm", {
  variants: {
    variant: {
      default: "border-slate-700 bg-slate-900/90 text-slate-200",
      info: "border-sky-500/40 bg-sky-500/10 text-sky-200",
      warning: "border-amber-500/40 bg-amber-500/10 text-amber-200",
      destructive: "border-red-500/40 bg-red-500/10 text-red-200",
      success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

export interface AlertProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, ...props }: AlertProps) {
  return <div role="alert" className={cn(alertVariants({ variant }), className)} {...props} />;
}
