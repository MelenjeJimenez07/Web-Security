"""Base plugin interfaces, FindingDraft schema, and scoring utilities for audit scanners."""

import hashlib
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.models.enums import ScanProfile, SeverityLevel, TargetType


def format_host_for_url(hostname: str) -> str:
    """Wrap IPv6 addresses in brackets when constructing URLs."""
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


@dataclass(slots=True)
class FindingDraft:
    """Structured finding produced by an audit plugin before DB persistence."""

    title: str
    technical_description: str
    severity: SeverityLevel
    owasp_category_code: str
    remediation_steps: str
    secondary_owasp_codes: list[str] = field(default_factory=list)
    affected_component: str | None = None
    cwe_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_snippets: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    def compute_fingerprint(self, *, normalized_target: str, module_key: str) -> str:
        """Compute deterministic SHA-256 hash to deduplicate findings across runs."""
        raw = "|".join(
            [
                normalized_target.lower(),
                module_key.lower(),
                self.owasp_category_code,
                self.title.strip().lower(),
                (self.affected_component or "").strip().lower(),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ModuleScanResult:
    """Result returned by an audit module execution."""

    module_key: str
    module_name: str
    findings: list[FindingDraft] = field(default_factory=list)
    raw_output: dict[str, Any] = field(default_factory=dict)
    summary_metrics: dict[str, Any] = field(default_factory=dict)
    skipped_reason: str | None = None


@dataclass(slots=True)
class ScanContext:
    """Immutable-intent runtime context passed into each audit module."""

    audit_run_id: uuid.UUID
    asset_id: uuid.UUID
    target_type: TargetType
    normalized_target: str
    hostname: str
    scheme: str | None
    port: int | None
    resolved_ip: str
    resolved_ips: tuple[str, ...]
    scan_profile: ScanProfile
    emit_log: Callable[[str, str, dict[str, Any] | None], None]

    def build_base_url(self, preferred_scheme: str | None = None, port_override: int | None = None) -> str:
        """Build an HTTP/HTTPS base URL for web-oriented scanners."""
        scheme = preferred_scheme or self.scheme or "https"
        port = port_override or self.port
        host = format_host_for_url(self.hostname)
        if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{host}"

    def log(self, message: str, level: str = "info", data: dict[str, Any] | None = None) -> None:
        """Emit a structured real-time log line to the streaming console."""
        self.emit_log(level, message, data)


class BaseAuditScanner(ABC):
    """Abstract base class for pluggable OWASP Top 10:2025 audit modules."""

    module_key: ClassVar[str]
    module_name: ClassVar[str]
    description: ClassVar[str]
    is_active: ClassVar[bool] = True
    default_owasp_categories: ClassVar[list[str]]

    @abstractmethod
    def run(self, ctx: ScanContext) -> ModuleScanResult:
        """Execute this audit module against the validated target in ctx."""


def score_to_grade(score: float) -> str:
    """Convert a 0-100 posture score to an A+..F security grade."""
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"
