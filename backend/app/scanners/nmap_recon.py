"""Module 1: Network Reconnaissance and Exposed Surface Scanner (Nmap wrapper)."""

from typing import Any

import nmap

from app.core.config import get_settings
from app.core.exceptions import ScannerExecutionError, SSRFBlockedError
from app.core.security import is_public_routable_ip, run_safe_command, safe_http_get
from app.models.enums import ScanProfile, SeverityLevel
from app.scanners.base import BaseAuditScanner, FindingDraft, ModuleScanResult, ScanContext

settings = get_settings()

# Parameterized Nmap arguments per profile using unprivileged TCP connect scan (-sT)
# and explicit '--' terminator to prevent argument injection.
_PROFILE_ARGS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["-sT", "-Pn", "-T4", "--top-ports", "100", "--open", "-oX", "-"],
    ScanProfile.TOP_1000: ["-sT", "-Pn", "-T4", "--top-ports", "1000", "--open", "-oX", "-"],
    ScanProfile.SERVICE_VERSION: [
        "-sT",
        "-sV",
        "--version-intensity",
        "5",
        "-Pn",
        "-T4",
        "--top-ports",
        "1000",
        "--open",
        "-oX",
        "-",
    ],
}

# Sensitive port classification table for uniform evaluation
_SENSITIVE_PORTS: dict[int, tuple[str, SeverityLevel, str, str, str]] = {
    21: (
        "FTP",
        SeverityLevel.HIGH,
        "A02:2025",
        "CWE-319",
        "Deshabilitar FTP en favor de SFTP/FTPS y restringir acceso por IP.",
    ),
    22: (
        "SSH",
        SeverityLevel.MEDIUM,
        "A01:2025",
        "CWE-284",
        "Restringir SSH a IPs de gestión/bastion/VPN, deshabilitar login con contraseña y exigir llaves.",
    ),
    23: (
        "Telnet",
        SeverityLevel.CRITICAL,
        "A02:2025",
        "CWE-319",
        "Cerrar el puerto 23 inmediatamente y migrar a acceso administrativo cifrado vía SSH sobre VPN.",
    ),
    2375: (
        "Docker Daemon HTTP (Sin TLS)",
        SeverityLevel.CRITICAL,
        "A01:2025",
        "CWE-306",
        "Cerrar el socket TCP 2375 al exterior de inmediato; usar socket Unix local o mTLS estricto.",
    ),
    3306: (
        "MySQL / MariaDB",
        SeverityLevel.HIGH,
        "A01:2025",
        "CWE-284",
        "Vincular MySQL exclusivamente a 127.0.0.1 o subred privada aislada y bloquear puerto 3306 en firewall.",
    ),
    3389: (
        "RDP (Remote Desktop)",
        SeverityLevel.HIGH,
        "A01:2025",
        "CWE-284",
        "No exponer RDP directamente a Internet; proteger detrás de VPN con MFA y Network Level Authentication.",
    ),
    5432: (
        "PostgreSQL",
        SeverityLevel.HIGH,
        "A01:2025",
        "CWE-284",
        "Restringir listen_addresses y pg_hba.conf a redes internas y cerrar el puerto 5432 al tráfico público.",
    ),
    5900: (
        "VNC",
        SeverityLevel.HIGH,
        "A01:2025",
        "CWE-284",
        "Cerrar puerto VNC público o encapsularlo mediante túnel SSH/VPN.",
    ),
    6379: (
        "Redis",
        SeverityLevel.CRITICAL,
        "A01:2025",
        "CWE-306",
        "Restringir Redis a red privada interna, habilitar ACL/requirepass y bloquear acceso desde Internet.",
    ),
    9200: (
        "Elasticsearch HTTP",
        SeverityLevel.HIGH,
        "A01:2025",
        "CWE-284",
        "Bloquear exposición pública de Elasticsearch y habilitar autenticación TLS + control de acceso.",
    ),
    11211: (
        "Memcached",
        SeverityLevel.HIGH,
        "A02:2025",
        "CWE-284",
        "Deshabilitar escucha pública UDP/TCP en Memcached y vincular a loopback o red interna.",
    ),
    27017: (
        "MongoDB",
        SeverityLevel.CRITICAL,
        "A01:2025",
        "CWE-284",
        "Cerrar el puerto 27017 al exterior, exigir autenticación SCRAM-SHA-256 y aislar en red privada.",
    ),
}

# Read-only check for accidentally exposed unauthenticated admin/diagnostic endpoints
_ADMIN_DIAGNOSTIC_PATHS: tuple[tuple[str, str, str, SeverityLevel], ...] = (
    ("/admin", "Panel Administrativo (/admin)", "A01:2025", SeverityLevel.MEDIUM),
    ("/administrator", "Panel Administrativo (/administrator)", "A01:2025", SeverityLevel.MEDIUM),
    ("/wp-admin/", "Panel WordPress (/wp-admin/)", "A01:2025", SeverityLevel.LOW),
    ("/phpmyadmin/", "Interfaz phpMyAdmin expuesta", "A01:2025", SeverityLevel.HIGH),
    ("/swagger-ui.html", "Documentación Swagger UI pública", "A02:2025", SeverityLevel.LOW),
    ("/docs", "Documentación interactiva OpenAPI (/docs)", "A02:2025", SeverityLevel.INFO),
    ("/actuator/health", "Endpoint Spring Boot Actuator expuesto", "A02:2025", SeverityLevel.LOW),
    ("/server-status", "Apache server-status expuesto", "A02:2025", SeverityLevel.MEDIUM),
)


class NmapReconScanner(BaseAuditScanner):
    """Network surface & port/service scanner using Nmap with anti-injection hardening."""

    module_key = "nmap_recon"
    module_name = "Reconocimiento de Red y Superficie Expuesta (Nmap)"
    description = (
        "Detecta puertos TCP abiertos, protocolos, versiones de servicios activos y paneles "
        "administrativos o endpoints de diagnóstico expuestos."
    )
    is_active = True
    default_owasp_categories = ["A02:2025", "A01:2025"]

    def run(self, ctx: ScanContext) -> ModuleScanResult:
        if not is_public_routable_ip(ctx.resolved_ip):
            raise SSRFBlockedError(
                f"IP objetivo '{ctx.resolved_ip}' rechazada antes de ejecutar Nmap."
            )

        profile_args = _PROFILE_ARGS.get(ctx.scan_profile, _PROFILE_ARGS[ScanProfile.QUICK])
        cmd = ["nmap", *profile_args, "--", ctx.resolved_ip]
        ctx.log(
            f"Iniciando escaneo Nmap (perfil '{ctx.scan_profile.value}') sobre IP validada {ctx.resolved_ip}",
            level="info",
            data={"profile": ctx.scan_profile.value, "target_ip": ctx.resolved_ip},
        )

        completed = run_safe_command(cmd, timeout_seconds=settings.MAX_SCAN_TIMEOUT_SECONDS)
        if completed.returncode != 0 and "<nmaprun" not in completed.stdout:
            raise ScannerExecutionError(
                f"Nmap finalizó con error (código {completed.returncode}): "
                f"{completed.stderr.strip()[:300]}"
            )

        scanner = nmap.PortScanner()
        parsed = scanner.analyse_nmap_xml_scan(nmap_xml_output=completed.stdout)
        scan_hosts = parsed.get("scan", {})
        host_data = scan_hosts.get(ctx.resolved_ip) or (next(iter(scan_hosts.values()), {}))

        open_ports: list[dict[str, Any]] = []
        tcp_ports = host_data.get("tcp", {}) if isinstance(host_data, dict) else {}

        for port_num, info in sorted(tcp_ports.items()):
            if info.get("state") != "open":
                continue
            open_ports.append(
                {
                    "port": int(port_num),
                    "protocol": "tcp",
                    "state": info.get("state", "open"),
                    "service": info.get("name", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "extrainfo": info.get("extrainfo", ""),
                }
            )

        ctx.log(
            f"Nmap detectó {len(open_ports)} puerto(s) TCP abierto(s).",
            level="info",
            data={"open_ports": [p["port"] for p in open_ports]},
        )

        findings: list[FindingDraft] = []
        self._evaluate_open_ports(open_ports, findings)
        exposed_endpoints = self._check_exposed_web_endpoints(ctx, open_ports, findings)

        if not findings and open_ports:
            findings.append(
                FindingDraft(
                    title="Superficie de red limitada a servicios estándar",
                    technical_description=(
                        f"Se identificaron {len(open_ports)} puerto(s) abierto(s) sin exposición de "
                        "bases de datos ni servicios heredados en texto plano."
                    ),
                    severity=SeverityLevel.INFO,
                    owasp_category_code="A02:2025",
                    affected_component=ctx.resolved_ip,
                    cwe_id="CWE-200",
                    evidence={"open_ports": open_ports},
                    remediation_steps=(
                        "Mantener revisión periódica de reglas de firewall para confirmar que cada "
                        "puerto abierto responde a una necesidad operativa documentada."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        return ModuleScanResult(
            module_key=self.module_key,
            module_name=self.module_name,
            findings=findings,
            raw_output={
                "profile": ctx.scan_profile.value,
                "scanned_ip": ctx.resolved_ip,
                "open_ports": open_ports,
                "exposed_endpoints": exposed_endpoints,
            },
            summary_metrics={
                "open_ports_count": len(open_ports),
                "exposed_endpoints_count": len(exposed_endpoints),
            },
        )

    def _evaluate_open_ports(
        self, open_ports: list[dict[str, Any]], findings: list[FindingDraft]
    ) -> None:
        version_disclosures: list[dict[str, Any]] = []

        for port_info in open_ports:
            port = port_info["port"]
            service_label = port_info["service"]
            banner = " ".join(
                part for part in (port_info["product"], port_info["version"]) if part
            ).strip()
            component = f"{port}/tcp ({banner or service_label})"

            if port in _SENSITIVE_PORTS:
                label, severity, owasp_code, cwe_id, remediation = _SENSITIVE_PORTS[port]
                secondary = ["A02:2025"] if owasp_code == "A01:2025" else ["A01:2025"]
                findings.append(
                    FindingDraft(
                        title=f"Servicio sensible '{label}' expuesto en puerto {port}/tcp",
                        technical_description=(
                            f"El escaneo detectó el puerto {port}/tcp ({service_label}) accesible "
                            "públicamente. La exposición directa de interfaces administrativas, bases "
                            "de datos o protocolos sin cifrar amplía la superficie de ataque y "
                            "vulnera el control de acceso perimetral."
                        ),
                        severity=severity,
                        owasp_category_code=owasp_code,
                        secondary_owasp_codes=secondary,
                        affected_component=component,
                        cwe_id=cwe_id,
                        evidence=port_info,
                        remediation_steps=remediation,
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )

            if banner:
                version_disclosures.append(port_info)

        if version_disclosures:
            findings.append(
                FindingDraft(
                    title="Exposición de banners y versiones de servicios en puertos de red",
                    technical_description=(
                        "Los servicios activos revelan información de producto y versión durante la "
                        "negociación TCP/banner, facilitando el reconocimiento dirigido de versiones."
                    ),
                    severity=SeverityLevel.LOW,
                    owasp_category_code="A02:2025",
                    affected_component=", ".join(
                        f"{p['port']}/tcp ({p['product']} {p['version']})".strip()
                        for p in version_disclosures
                    ),
                    cwe_id="CWE-200",
                    evidence={"services_with_banners": version_disclosures},
                    remediation_steps=(
                        "Deshabilitar o minimizar los banners de versión en servidores web, proxies "
                        "y demonios de red (ej. 'server_tokens off;' en Nginx, 'ServerTokens Prod' "
                        "en Apache)."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

    def _check_exposed_web_endpoints(
        self,
        ctx: ScanContext,
        open_ports: list[dict[str, Any]],
        findings: list[FindingDraft],
    ) -> list[dict[str, Any]]:
        open_port_nums = {p["port"] for p in open_ports}
        has_web_surface = bool(open_port_nums & {80, 443, 8080, 8443}) or ctx.scheme in {
            "http",
            "https",
        }
        if not has_web_surface:
            return []

        if 443 in open_port_nums or ctx.scheme == "https" and (80 not in open_port_nums or 443 in open_port_nums):
            base_url = ctx.build_base_url()
        elif 80 in open_port_nums:
            base_url = ctx.build_base_url(preferred_scheme="http", port_override=80)
        elif 8443 in open_port_nums:
            base_url = ctx.build_base_url(preferred_scheme="https", port_override=8443)
        elif 8080 in open_port_nums:
            base_url = ctx.build_base_url(preferred_scheme="http", port_override=8080)
        else:
            base_url = ctx.build_base_url()

        exposed: list[dict[str, Any]] = []
        ctx.log("Verificando exposición pasiva de rutas administrativas y de diagnóstico...")

        for path, label, owasp_code, severity in _ADMIN_DIAGNOSTIC_PATHS:
            probe_url = f"{base_url}{path}"
            try:
                response, chain = safe_http_get(
                    probe_url,
                    timeout_seconds=6.0,
                    max_redirects=2,
                    verify_tls=False,
                )
            except SSRFBlockedError:
                raise
            except Exception:
                continue

            if response.status_code == 200:
                entry = {
                    "path": path,
                    "url": response.url,
                    "status_code": response.status_code,
                    "redirect_chain": chain,
                }
                exposed.append(entry)
                findings.append(
                    FindingDraft(
                        title=f"Endpoint sensible accesible sin bloqueo perimetral: {path}",
                        technical_description=(
                            f"La ruta '{label}' respondió con HTTP 200 OK en {response.url}. "
                            "Si este endpoint no requiere acceso público, expone superficies "
                            "administrativas o metadatos técnicos internos."
                        ),
                        severity=severity,
                        owasp_category_code=owasp_code,
                        secondary_owasp_codes=["A02:2025"] if owasp_code == "A01:2025" else [],
                        affected_component=response.url,
                        cwe_id="CWE-284" if owasp_code == "A01:2025" else "CWE-200",
                        evidence=entry,
                        remediation_steps=(
                            f"Restringir '{path}' mediante autenticación robusta/MFA, lista blanca "
                            "de IPs o deshabilitar la ruta en entornos de producción."
                        ),
                        remediation_snippets={
                            "nginx": (
                                f"location ^~ {path} {{\n"
                                "    allow 10.0.0.0/8;\n"
                                "    deny all;\n"
                                "}"
                            ),
                            "apache": (
                                f"<Location \"{path}\">\n"
                                "    Require ip 10.0.0.0/8\n"
                                "</Location>"
                            ),
                        },
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )

        return exposed
