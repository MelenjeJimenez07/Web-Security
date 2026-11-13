"""Domain and security enumerations shared across ORM models and API schemas."""

import enum


class TargetType(str, enum.Enum):
    """Supported asset target types."""

    DOMAIN = "domain"
    URL = "url"
    IP = "ip"


class VerificationMethod(str, enum.Enum):
    """Authorized domain ownership verification methods."""

    DNS_TXT = "dns_txt"
    WELL_KNOWN_FILE = "well_known_file"


class VerificationStatus(str, enum.Enum):
    """Lifecycle status of an ownership verification challenge."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class ScanProfile(str, enum.Enum):
    """Configurable Nmap/network reconnaissance profiles."""

    QUICK = "quick"
    TOP_1000 = "top_1000"
    SERVICE_VERSION = "service_version"


class AuditStatus(str, enum.Enum):
    """Overall lifecycle status of an audit run."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL_FAILURE = "partial_failure"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModuleStatus(str, enum.Enum):
    """Execution status of an individual audit plugin module."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    """Standardized 5-level security finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    """Triage status of a discovered finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"


class ReportFormat(str, enum.Enum):
    """Exportable report file formats."""

    PDF = "pdf"
    JSON = "json"


class ReportType(str, enum.Enum):
    """Exportable report detail levels."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    FULL = "full"
