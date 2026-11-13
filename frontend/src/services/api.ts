import type {
  Asset,
  AssetCreatePayload,
  AssetDetail,
  AuditLaunchPayload,
  AuditReport,
  AuditRunDetail,
  AuditRunSummary,
  DashboardStats,
  DomainVerification,
  Finding,
  FindingStatus,
  OwaspCategory,
  ReportFormat,
  ReportType,
  ScannerInfo,
  SecurityEventLog,
  StreamLogEvent,
  VerificationCheckResponse,
  VerificationMethod,
} from "@/types/api";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "/api/v1").replace(/\/$/, "");
const WS_BASE = (import.meta.env.VITE_WS_BASE_URL || "/ws").replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  code: string;
  correlationId?: string;
  details?: unknown;

  constructor(
    message: string,
    status: number,
    code = "API_ERROR",
    correlationId?: string,
    details?: unknown
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.details = details;
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    const errObj =
      body && typeof body === "object" && "error" in body
        ? (body as { error: { code?: string; message?: string; correlation_id?: string; details?: unknown } }).error
        : null;
    throw new ApiError(
      errObj?.message || `Error HTTP ${response.status} al consultar ${path}`,
      response.status,
      errObj?.code || `HTTP_${response.status}`,
      errObj?.correlation_id,
      errObj?.details
    );
  }

  return body as T;
}

export const api = {
  getDashboardStats: () => requestJson<DashboardStats>("/dashboard/stats"),

  listOwaspCategories: () => requestJson<OwaspCategory[]>("/owasp/categories"),

  listScanners: () => requestJson<ScannerInfo[]>("/scanners"),

  listAssets: () => requestJson<Asset[]>("/assets"),

  getAsset: (assetId: string) => requestJson<AssetDetail>(`/assets/${assetId}`),

  createAsset: (payload: AssetCreatePayload) =>
    requestJson<Asset>("/assets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteAsset: (assetId: string) =>
    requestJson<void>(`/assets/${assetId}`, {
      method: "DELETE",
    }),

  createVerificationChallenge: (assetId: string, method: VerificationMethod) =>
    requestJson<DomainVerification>(`/assets/${assetId}/verifications`, {
      method: "POST",
      body: JSON.stringify({ method }),
    }),

  checkVerificationChallenge: (assetId: string, verificationId: string) =>
    requestJson<VerificationCheckResponse>(
      `/assets/${assetId}/verifications/${verificationId}/check`,
      { method: "POST" }
    ),

  listAudits: (assetId?: string) => {
    const query = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
    return requestJson<AuditRunSummary[]>(`/audits${query}`);
  },

  launchAudit: (payload: AuditLaunchPayload) =>
    requestJson<AuditRunDetail>("/audits", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getAuditDetail: (auditId: string) => requestJson<AuditRunDetail>(`/audits/${auditId}`),

  listAuditFindings: (
    auditId: string,
    filters?: {
      severity?: string;
      owasp_category_code?: string;
      module_key?: string;
      status?: string;
    }
  ) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.owasp_category_code) params.set("owasp_category_code", filters.owasp_category_code);
    if (filters?.module_key) params.set("module_key", filters.module_key);
    if (filters?.status) params.set("status", filters.status);
    const qs = params.toString();
    return requestJson<Finding[]>(`/audits/${auditId}/findings${qs ? `?${qs}` : ""}`);
  },

  updateFindingStatus: (findingId: string, status: FindingStatus) =>
    requestJson<Finding>(`/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  getAuditLogs: (auditId: string) =>
    requestJson<{
      audit_run_id: string;
      status: string;
      stream_logs: StreamLogEvent[];
      security_events: SecurityEventLog[];
    }>(`/audits/${auditId}/logs`),

  listSecurityLogs: (eventType?: string) => {
    const qs = eventType ? `?event_type=${encodeURIComponent(eventType)}` : "";
    return requestJson<SecurityEventLog[]>(`/security-logs${qs}`);
  },

  listAuditReports: (auditId: string) =>
    requestJson<AuditReport[]>(`/audits/${auditId}/reports`),

  generateAuditReport: (
    auditId: string,
    payload: { format: ReportFormat; report_type: ReportType; generated_by?: string }
  ) =>
    requestJson<AuditReport>(`/audits/${auditId}/reports`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getReportDownloadUrl: (reportId: string): string =>
    `${API_BASE}/reports/${reportId}/download`,

  buildAuditWebSocketUrl: (auditId: string): string => {
    if (WS_BASE.startsWith("ws://") || WS_BASE.startsWith("wss://")) {
      return `${WS_BASE}/audits/${auditId}`;
    }
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}${WS_BASE}/audits/${auditId}`;
  },

  buildAuditSseUrl: (auditId: string): string => `${API_BASE}/audits/${auditId}/events`,
};
