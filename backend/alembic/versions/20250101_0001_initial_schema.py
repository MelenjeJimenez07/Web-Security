"""Initial schema with OWASP Top 10:2025 catalog, assets, audits, findings, logs, and reports.

Revision ID: 20250101_0001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.owasp_catalog import OWASP_TOP_10_2025_CATALOG

# revision identifiers, used by Alembic.
revision: str = "20250101_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB_VARIANT = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

# Enum definitions (created once explicitly to prevent DuplicateObject errors)
target_type_enum = postgresql.ENUM("domain", "url", "ip", name="target_type", create_type=False)
verification_method_enum = postgresql.ENUM(
    "dns_txt", "well_known_file", name="verification_method", create_type=False
)
verification_status_enum = postgresql.ENUM(
    "pending", "verified", "failed", "expired", name="verification_status", create_type=False
)
scan_profile_enum = postgresql.ENUM(
    "quick", "top_1000", "service_version", name="scan_profile", create_type=False
)
audit_status_enum = postgresql.ENUM(
    "pending",
    "queued",
    "running",
    "completed",
    "partial_failure",
    "failed",
    "cancelled",
    name="audit_status",
    create_type=False,
)
module_status_enum = postgresql.ENUM(
    "pending", "running", "completed", "skipped", "failed", name="module_status", create_type=False
)
severity_level_enum = postgresql.ENUM(
    "info", "low", "medium", "high", "critical", name="severity_level", create_type=False
)
finding_status_enum = postgresql.ENUM(
    "open",
    "acknowledged",
    "mitigated",
    "false_positive",
    name="finding_status",
    create_type=False,
)
report_format_enum = postgresql.ENUM("pdf", "json", name="report_format", create_type=False)
report_type_enum = postgresql.ENUM(
    "executive", "technical", "full", name="report_type", create_type=False
)

ALL_ENUMS = (
    target_type_enum,
    verification_method_enum,
    verification_status_enum,
    scan_profile_enum,
    audit_status_enum,
    module_status_enum,
    severity_level_enum,
    finding_status_enum,
    report_format_enum,
    report_type_enum,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in ALL_ENUMS:
        enum_type.create(bind, checkfirst=True)

    # 1. OWASP Top 10:2025 Catalog
    owasp_table = op.create_table(
        "owasp_categories",
        sa.Column("code", sa.String(length=16), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("name_es", sa.String(length=150), nullable=False),
        sa.Column("short_summary", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
        sa.Column("cwe_examples", JSONB_VARIANT, nullable=False),
        sa.Column("is_new_in_2025", sa.Boolean(), nullable=False),
        sa.Column("reference_url", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("code", name="pk_owasp_categories"),
        sa.UniqueConstraint("rank", name="uq_owasp_categories_rank"),
    )

    # Seed OWASP Top 10:2025 categories
    op.bulk_insert(owasp_table, OWASP_TOP_10_2025_CATALOG)

    # 2. Assets
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("target_type", target_type_enum, nullable=False),
        sa.Column("normalized_target", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("scheme", sa.String(length=16), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("resolved_ip", sa.String(length=45), nullable=True),
        sa.Column("environment", sa.String(length=50), nullable=False),
        sa.Column("owner_email", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_method", verification_method_enum, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=False)
    op.create_index("ix_assets_is_verified", "assets", ["is_verified"], unique=False)
    op.create_index("ix_assets_normalized_target", "assets", ["normalized_target"], unique=True)

    # 3. Domain Verifications
    op.create_table(
        "domain_verifications",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("method", verification_method_enum, nullable=False),
        sa.Column("challenge_token", sa.String(length=128), nullable=False),
        sa.Column("expected_location", sa.String(length=512), nullable=False),
        sa.Column("status", verification_status_enum, nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_domain_verifications_asset_id_assets",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_domain_verifications"),
    )
    op.create_index(
        "ix_domain_verifications_asset_id", "domain_verifications", ["asset_id"], unique=False
    )
    op.create_index(
        "ix_domain_verifications_challenge_token",
        "domain_verifications",
        ["challenge_token"],
        unique=True,
    )
    op.create_index(
        "ix_domain_verifications_status", "domain_verifications", ["status"], unique=False
    )

    # 4. Audit Runs
    op.create_table(
        "audit_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("status", audit_status_enum, nullable=False),
        sa.Column("scan_profile", scan_profile_enum, nullable=False),
        sa.Column("selected_modules", JSONB_VARIANT, nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("authorization_statement", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=150), nullable=False),
        sa.Column("requester_ip", sa.String(length=45), nullable=True),
        sa.Column("ownership_verified_at_launch", sa.Boolean(), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("current_stage", sa.String(length=120), nullable=True),
        sa.Column("security_grade", sa.String(length=4), nullable=True),
        sa.Column("security_score", sa.Float(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.Column("info_count", sa.Integer(), nullable=False),
        sa.Column("summary_metadata", JSONB_VARIANT, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "authorization_confirmed = true", name="ck_audit_runs_authorization_confirmed_true"
        ),
        sa.CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_audit_runs_progress_percent_bounds",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_audit_runs_asset_id_assets",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_runs"),
    )
    op.create_index("ix_audit_runs_asset_id", "audit_runs", ["asset_id"], unique=False)
    op.create_index("ix_audit_runs_celery_task_id", "audit_runs", ["celery_task_id"], unique=False)
    op.create_index("ix_audit_runs_status", "audit_runs", ["status"], unique=False)

    # 5. Audit Module Executions
    op.create_table(
        "audit_module_executions",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("audit_run_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("module_key", sa.String(length=64), nullable=False),
        sa.Column("module_name", sa.String(length=150), nullable=False),
        sa.Column("status", module_status_enum, nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("raw_output", JSONB_VARIANT, nullable=False),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["audit_run_id"],
            ["audit_runs.id"],
            name="fk_audit_module_executions_audit_run_id_audit_runs",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_module_executions"),
        sa.UniqueConstraint("audit_run_id", "module_key", name="uq_audit_module_run_key"),
    )
    op.create_index(
        "ix_audit_module_executions_audit_run_id",
        "audit_module_executions",
        ["audit_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_module_executions_module_key",
        "audit_module_executions",
        ["module_key"],
        unique=False,
    )

    # 6. Findings
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("audit_run_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("module_execution_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("module_key", sa.String(length=64), nullable=False),
        sa.Column("owasp_category_code", sa.String(length=16), nullable=False),
        sa.Column("secondary_owasp_codes", JSONB_VARIANT, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("technical_description", sa.Text(), nullable=False),
        sa.Column("severity", severity_level_enum, nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cwe_id", sa.String(length=32), nullable=True),
        sa.Column("cve_ids", JSONB_VARIANT, nullable=False),
        sa.Column("affected_component", sa.String(length=255), nullable=True),
        sa.Column("evidence", JSONB_VARIANT, nullable=False),
        sa.Column("remediation_steps", sa.Text(), nullable=False),
        sa.Column("remediation_snippets", JSONB_VARIANT, nullable=False),
        sa.Column("references", JSONB_VARIANT, nullable=False),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=False),
        sa.Column("status", finding_status_enum, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["audit_run_id"],
            ["audit_runs.id"],
            name="fk_findings_audit_run_id_audit_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["module_execution_id"],
            ["audit_module_executions.id"],
            name="fk_findings_module_execution_id_audit_module_executions",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["owasp_category_code"],
            ["owasp_categories.code"],
            name="fk_findings_owasp_category_code_owasp_categories",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_audit_run_id", "findings", ["audit_run_id"], unique=False)
    op.create_index("ix_findings_fingerprint_hash", "findings", ["fingerprint_hash"], unique=False)
    op.create_index(
        "ix_findings_module_execution_id", "findings", ["module_execution_id"], unique=False
    )
    op.create_index("ix_findings_module_key", "findings", ["module_key"], unique=False)
    op.create_index(
        "ix_findings_owasp_category_code", "findings", ["owasp_category_code"], unique=False
    )
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("ix_findings_status", "findings", ["status"], unique=False)

    # 7. Security Event Logs (A09:2025)
    op.create_table(
        "security_event_logs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("audit_run_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("asset_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("actor", sa.String(length=150), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", JSONB_VARIANT, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name="fk_security_event_logs_asset_id_assets",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["audit_run_id"],
            ["audit_runs.id"],
            name="fk_security_event_logs_audit_run_id_audit_runs",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_event_logs"),
    )
    op.create_index(
        "ix_security_event_logs_asset_id", "security_event_logs", ["asset_id"], unique=False
    )
    op.create_index(
        "ix_security_event_logs_audit_run_id",
        "security_event_logs",
        ["audit_run_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_event_logs_created_at", "security_event_logs", ["created_at"], unique=False
    )
    op.create_index(
        "ix_security_event_logs_event_type", "security_event_logs", ["event_type"], unique=False
    )

    # 8. Audit Reports
    op.create_table(
        "audit_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("audit_run_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("format", report_format_enum, nullable=False),
        sa.Column("report_type", report_type_enum, nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("file_path", sa.String(length=512), nullable=False),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256_checksum", sa.String(length=64), nullable=False),
        sa.Column("generated_by", sa.String(length=150), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["audit_run_id"],
            ["audit_runs.id"],
            name="fk_audit_reports_audit_run_id_audit_runs",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_reports"),
    )
    op.create_index(
        "ix_audit_reports_audit_run_id", "audit_reports", ["audit_run_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_audit_reports_audit_run_id", table_name="audit_reports")
    op.drop_table("audit_reports")

    op.drop_index("ix_security_event_logs_event_type", table_name="security_event_logs")
    op.drop_index("ix_security_event_logs_created_at", table_name="security_event_logs")
    op.drop_index("ix_security_event_logs_audit_run_id", table_name="security_event_logs")
    op.drop_index("ix_security_event_logs_asset_id", table_name="security_event_logs")
    op.drop_table("security_event_logs")

    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_owasp_category_code", table_name="findings")
    op.drop_index("ix_findings_module_key", table_name="findings")
    op.drop_index("ix_findings_module_execution_id", table_name="findings")
    op.drop_index("ix_findings_fingerprint_hash", table_name="findings")
    op.drop_index("ix_findings_audit_run_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_audit_module_executions_module_key", table_name="audit_module_executions")
    op.drop_index("ix_audit_module_executions_audit_run_id", table_name="audit_module_executions")
    op.drop_table("audit_module_executions")

    op.drop_index("ix_audit_runs_status", table_name="audit_runs")
    op.drop_index("ix_audit_runs_celery_task_id", table_name="audit_runs")
    op.drop_index("ix_audit_runs_asset_id", table_name="audit_runs")
    op.drop_table("audit_runs")

    op.drop_index("ix_domain_verifications_status", table_name="domain_verifications")
    op.drop_index("ix_domain_verifications_challenge_token", table_name="domain_verifications")
    op.drop_index("ix_domain_verifications_asset_id", table_name="domain_verifications")
    op.drop_table("domain_verifications")

    op.drop_index("ix_assets_normalized_target", table_name="assets")
    op.drop_index("ix_assets_is_verified", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_table("assets")

    op.drop_table("owasp_categories")

    bind = op.get_bind()
    for enum_type in reversed(ALL_ENUMS):
        enum_type.drop(bind, checkfirst=True)
