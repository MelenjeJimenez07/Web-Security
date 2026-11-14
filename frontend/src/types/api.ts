export type TargetType = "domain" | "url" | "ip";
export type VerificationMethod = "dns_txt" | "well_known_file";
export type VerificationStatus = "pending" | "verified" | "failed" | "expired";
export type ScanProfile = "quick" | "top_1000" | "service_version";
export type AuditStatus =
  | "pending"
  | "queued"
  | "running"
  | "completed"
  | "partial_failure"
  | "failed"
  | "cancelled";
export type ModuleStatus = "pending" | "running" | "completed" | "skipped" | "failed";
export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "acknowledged" | "mitigated" | "false_positive";
export type ReportFormat = "pdf" | "json" | "docx";
export type ReportType = "executive" | "technical" | "full";

export interface AuditReport {
  id: string;
  audit_run_id: string;
  format: ReportFormat;
  report_type: ReportType;
  file_name: string;
  file_size_bytes: number;
  sha256_checksum: string;
  generated_by: string | null;
  created_at: string;
  download_url: string;
}

export interface OwaspCategory {
  code: string;
  rank: number;
  name: string;
  name_es: string;
  short_summary: string;
  description: string;
  remediation_guidance: string;
  cwe_examples: string[];
  is_new_in_2025: boolean;
  reference_url: string;
}

export interface DomainVerification {
  id: string;
  asset_id: string;
  method: VerificationMethod;
  challenge_token: string;
  expected_location: string;
  status: VerificationStatus;
  last_checked_at: string | null;
  verified_at: string | null;
  failure_reason: string | null;
  expires_at: string;
  created_at: string;
  instructions: string | null;
}

export interface Asset {
  id: string;
  name: string;
  target_type: TargetType;
  normalized_target: string;
  hostname: string;
  scheme: string | null;
  port: number | null;
  resolved_ip: string | null;
  environment: string;
  owner_email: string | null;
  notes: string | null;
  is_verified: boolean;
  verified_at: string | null;
  verification_method: VerificationMethod | null;
  created_at: string;
  updated_at: string;
}

export interface AssetDetail extends Asset {
  verifications: DomainVerification[];
}

export interface VerificationCheckResponse {
  verified: boolean;
  message: string;
  verification: DomainVerification;
}

export interface ScannerInfo {
  module_key: string;
  module_name: string;
  description: string;
  is_active: boolean;
  default_owasp_categories: string[];
}

export interface AuditModuleExecution {
  id: string;
  audit_run_id: string;
  module_key: string;
  module_name: string;
  status: ModuleStatus;
  findings_count: number;
  duration_ms: number | null;
  raw_output: Record<string, unknown>;
  error_detail: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface OwaspDistributionItem {
  code: string;
  rank: number;
  name: string;
  name_es: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AuditRunSummary {
  id: string;
  asset_id: string;
  asset_name: string | null;
  asset_target: string | null;
  celery_task_id: string | null;
  status: AuditStatus;
  scan_profile: ScanProfile;
  selected_modules: string[];
  authorization_confirmed: boolean;
  requested_by: string;
  ownership_verified_at_launch: boolean;
  progress_percent: number;
  current_stage: string | null;
  security_grade: string | null;
  security_score: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  summary_metadata: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface AuditRunDetail extends AuditRunSummary {
  authorization_statement: string;
  asset: Asset;
  module_executions: AuditModuleExecution[];
  owasp_distribution: OwaspDistributionItem[];
}

export interface Finding {
  id: string;
  audit_run_id: string;
  module_execution_id: string | null;
  module_key: string;
  owasp_category_code: string;
  secondary_owasp_codes: string[];
  title: string;
  technical_description: string;
  severity: SeverityLevel;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_id: string | null;
  cve_ids: string[];
  affected_component: string | null;
  evidence: Record<string, unknown>;
  remediation_steps: string;
  remediation_snippets: Record<string, string>;
  references: string[];
  fingerprint_hash: string;
  status: FindingStatus;
  created_at: string;
  owasp_category_name: string | null;
  owasp_category_name_es: string | null;
}

export interface StreamLogEvent {
  audit_run_id?: string;
  timestamp?: string;
  event_type: string;
  level?: string;
  module_key?: string | null;
  progress_percent?: number | null;
  message?: string;
  status?: AuditStatus;
  data?: Record<string, unknown>;
}

export interface SecurityEventLog {
  id: string;
  audit_run_id: string | null;
  asset_id: string | null;
  event_type: string;
  severity: string;
  actor: string | null;
  source_ip: string | null;
  message: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface DashboardStats {
  total_assets: number;
  verified_assets: number;
  total_audits: number;
  active_audits: number;
  total_findings: number;
  severity_distribution: Record<SeverityLevel, number>;
  owasp_distribution: OwaspDistributionItem[];
  recent_audits: AuditRunSummary[];
}

export interface AssetCreatePayload {
  name: string;
  target: string;
  environment: string;
  owner_email?: string;
  notes?: string;
}

export interface AuditLaunchPayload {
  asset_id: string;
  scan_profile: ScanProfile;
  selected_modules: string[];
  authorization_confirmed: boolean;
  authorization_statement: string;
  requested_by: string;
}
