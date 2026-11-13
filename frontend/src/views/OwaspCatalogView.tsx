import { BookOpen, ExternalLink, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { OwaspCategory } from "@/types/api";

interface OwaspCatalogViewProps {
  categories: OwaspCategory[];
}

export function OwaspCatalogView({ categories }: OwaspCatalogViewProps) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Estándar OWASP Top 10:2025
        </h1>
        <p className="text-sm text-slate-400">
          Catálogo de referencia oficial almacenado en PostgreSQL para clasificar automáticamente cada hallazgo.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {categories.map((cat) => (
          <Card key={cat.code} className="flex flex-col justify-between">
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Badge variant="default" className="font-mono text-xs">
                    #{cat.rank} • {cat.code}
                  </Badge>
                  {cat.is_new_in_2025 && (
                    <Badge variant="warning">
                      <Sparkles className="h-3 w-3" />
                      Nuevo / Ampliado 2025
                    </Badge>
                  )}
                </div>
                <a
                  href={cat.reference_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
                >
                  <BookOpen className="h-3.5 w-3.5" />
                  OWASP
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
              <CardTitle className="pt-1 text-base">{cat.name_es}</CardTitle>
              <CardDescription>{cat.name}</CardDescription>
            </CardHeader>

            <CardContent className="space-y-3 text-xs leading-relaxed text-slate-300">
              <p>{cat.description}</p>
              <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3">
                <p className="mb-1 font-semibold text-emerald-300">Guía de Mitigación</p>
                <p className="text-slate-300">{cat.remediation_guidance}</p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {cat.cwe_examples.map((cwe) => (
                  <Badge key={cwe} variant="secondary" className="font-mono text-[10px]">
                    {cwe}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
