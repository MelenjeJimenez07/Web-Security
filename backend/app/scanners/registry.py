"""Plugin registry for all modular OWASP Top 10:2025 audit scanners."""

from app.core.exceptions import TargetValidationError
from app.scanners.base import BaseAuditScanner
from app.scanners.dns_passive import DnsPassiveScanner
from app.scanners.http_headers import HttpHeadersScanner
from app.scanners.nmap_recon import NmapReconScanner
from app.scanners.ssl_tls import SslTlsScanner
from app.scanners.tech_supply_chain import TechSupplyChainScanner

_SCANNER_CLASSES: tuple[type[BaseAuditScanner], ...] = (
    DnsPassiveScanner,
    NmapReconScanner,
    SslTlsScanner,
    HttpHeadersScanner,
    TechSupplyChainScanner,
)

SCANNER_REGISTRY: dict[str, BaseAuditScanner] = {
    cls.module_key: cls() for cls in _SCANNER_CLASSES
}


def get_all_module_keys() -> list[str]:
    """Return ordered list of registered audit module keys."""
    return list(SCANNER_REGISTRY.keys())


def get_scanner(module_key: str) -> BaseAuditScanner:
    """Return scanner plugin instance by key."""
    scanner = SCANNER_REGISTRY.get(module_key)
    if scanner is None:
        raise TargetValidationError(f"Módulo de auditoría desconocido: '{module_key}'.")
    return scanner


def validate_module_keys(module_keys: list[str] | None) -> list[str]:
    """Validate and deduplicate requested module keys, defaulting to all modules."""
    if not module_keys:
        return get_all_module_keys()

    ordered_unique: list[str] = []
    for key in module_keys:
        if key not in SCANNER_REGISTRY:
            raise TargetValidationError(
                f"Módulo de auditoría inválido: '{key}'. Módulos válidos: {get_all_module_keys()}"
            )
        if key not in ordered_unique:
            ordered_unique.append(key)
    return ordered_unique


def has_active_modules(module_keys: list[str]) -> bool:
    """Return True if any selected module performs active network/HTTP probing."""
    return any(SCANNER_REGISTRY[key].is_active for key in module_keys)


def list_scanners_metadata() -> list[dict[str, object]]:
    """Return descriptor list for frontend scan launcher and API documentation."""
    return [
        {
            "module_key": scanner.module_key,
            "module_name": scanner.module_name,
            "description": scanner.description,
            "is_active": scanner.is_active,
            "default_owasp_categories": scanner.default_owasp_categories,
        }
        for scanner in SCANNER_REGISTRY.values()
    ]
