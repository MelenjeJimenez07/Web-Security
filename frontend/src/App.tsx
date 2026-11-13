import { useCallback, useEffect, useState } from "react";
import { Sidebar, type NavSection } from "@/components/layout/Sidebar";
import { Alert } from "@/components/ui/alert";
import { api } from "@/services/api";
import type {
  Asset,
  AuditRunSummary,
  DashboardStats,
  OwaspCategory,
  ScannerInfo,
  SecurityEventLog,
} from "@/types/api";
import { AssetsVerificationView } from "@/views/AssetsVerificationView";
import { AuditDetailView } from "@/views/AuditDetailView";
import { LaunchAuditView } from "@/views/LaunchAuditView";
import { OverviewView } from "@/views/OverviewView";
import { OwaspCatalogView } from "@/views/OwaspCatalogView";
import { SecurityLogsView } from "@/views/SecurityLogsView";

export default function App() {
  const [section, setSection] = useState<NavSection>("overview");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [audits, setAudits] = useState<AuditRunSummary[]>([]);
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [owaspCategories, setOwaspCategories] = useState<OwaspCategory[]>([]);
  const [securityLogs, setSecurityLogs] = useState<SecurityEventLog[]>([]);

  const [selectedAssetForLaunch, setSelectedAssetForLaunch] = useState<string | null>(null);
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [globalError, setGlobalError] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setGlobalError(null);
    try {
      const [statsRes, assetsRes, auditsRes, scannersRes, owaspRes, logsRes] = await Promise.all([
        api.getDashboardStats(),
        api.listAssets(),
        api.listAudits(),
        api.listScanners(),
        api.listOwaspCategories(),
        api.listSecurityLogs(),
      ]);
      setStats(statsRes);
      setAssets(assetsRes);
      setAudits(auditsRes);
      setScanners(scannersRes);
      setOwaspCategories(owaspRes);
      setSecurityLogs(logsRes);
    } catch {
      setGlobalError(
        "No se pudo conectar con la API FastAPI (/api/v1). Verifica que los contenedores backend y postgres estén activos."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const refreshAssets = async () => {
    const [assetsRes, statsRes] = await Promise.all([api.listAssets(), api.getDashboardStats()]);
    setAssets(assetsRes);
    setStats(statsRes);
  };

  const refreshAudits = async () => {
    const [auditsRes, statsRes] = await Promise.all([api.listAudits(), api.getDashboardStats()]);
    setAudits(auditsRes);
    setStats(statsRes);
  };

  const refreshSecurityLogs = async () => {
    const logsRes = await api.listSecurityLogs();
    setSecurityLogs(logsRes);
  };

  const handleOpenAudit = (auditId: string) => {
    setSelectedAuditId(auditId);
    setSection("audits");
  };

  const handleLaunchForAsset = (assetId: string) => {
    setSelectedAssetForLaunch(assetId);
    setSection("launch");
  };

  const handleAuditLaunched = async (auditId: string) => {
    await refreshAudits();
    setSelectedAuditId(auditId);
    setSection("audits");
  };

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground lg:flex-row">
      <Sidebar
        activeSection={section}
        onSelect={(next) => {
          setSection(next);
          if (next === "logs") {
            void refreshSecurityLogs();
          }
        }}
        activeAuditsCount={stats?.active_audits ?? 0}
      />

      <main className="flex-1 overflow-x-hidden p-4 sm:p-6 lg:p-8">
        <div className="mx-auto max-w-7xl space-y-6">
          {globalError && <Alert variant="destructive">{globalError}</Alert>}

          {section === "overview" && (
            <OverviewView
              stats={stats}
              loading={loading}
              onRefresh={() => void loadAll()}
              onNavigateLaunch={() => setSection("launch")}
              onNavigateAssets={() => setSection("assets")}
              onOpenAudit={handleOpenAudit}
            />
          )}

          {section === "assets" && (
            <AssetsVerificationView
              assets={assets}
              onRefreshAssets={refreshAssets}
              onLaunchForAsset={handleLaunchForAsset}
            />
          )}

          {section === "launch" && (
            <LaunchAuditView
              assets={assets}
              scanners={scanners}
              preselectedAssetId={selectedAssetForLaunch}
              onGoToAssets={() => setSection("assets")}
              onAuditLaunched={(id) => void handleAuditLaunched(id)}
            />
          )}

          {section === "audits" && (
            <AuditDetailView
              audits={audits}
              selectedAuditId={selectedAuditId}
              onSelectAudit={setSelectedAuditId}
              onRefreshList={refreshAudits}
            />
          )}

          {section === "owasp" && <OwaspCatalogView categories={owaspCategories} />}

          {section === "logs" && (
            <SecurityLogsView
              logs={securityLogs}
              onRefresh={() => void refreshSecurityLogs()}
            />
          )}
        </div>
      </main>
    </div>
  );
}
