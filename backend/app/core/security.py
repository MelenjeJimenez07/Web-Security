"""Self-hardening security controls: Anti-SSRF, Anti-Command Injection, and Ownership Verification."""

import ipaddress
import re
import secrets
import socket
import subprocess
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import httpx

from app.core.config import get_settings
from app.core.exceptions import SSRFBlockedError, TargetValidationError
from app.models.enums import TargetType, VerificationMethod

settings = get_settings()

# Strict RFC-1123 hostname validation (prevents shell metacharacters & CLI option injection)
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
_FORBIDDEN_CHARS_RE = re.compile(r"[\s;&|`$<>\\\'\"!\(\)\{\}\[\]\n\r\t]")

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata",
    }
)
_BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".lan",
)

# Explicit CIDRs blocked to prevent SSRF against RFC1918, loopback, metadata, CGNAT, and multicast
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / RFC 6598
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local & Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),  # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),  # IPv6 Multicast
    ipaddress.ip_network("2001:db8::/32"),  # IPv6 Documentation
)

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_SAFE_HTTP_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB response read cap


@dataclass(frozen=True, slots=True)
class SafeHttpResponse:
    """Bounded, SSRF-checked HTTP response snapshot."""

    status_code: int
    url: str
    headers: httpx.Headers
    set_cookies: tuple[str, ...]
    content: bytes
    text: str


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """Normalized and SSRF-validated audit target."""

    target_type: TargetType
    normalized_target: str
    hostname: str
    scheme: str | None
    port: int | None
    resolved_ip: str
    resolved_ips: tuple[str, ...]


def is_public_routable_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a publicly routable global IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return is_public_routable_ip(str(ip_obj.ipv4_mapped))

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    ):
        return False

    for network in _BLOCKED_NETWORKS:
        if ip_obj in network:
            return False

    return True


def _validate_hostname_syntax(hostname: str) -> None:
    if not hostname or len(hostname) > 253:
        raise TargetValidationError("El hostname está vacío o excede 253 caracteres.")
    if hostname.startswith("-"):
        raise TargetValidationError("Hostname inválido: no puede comenzar con '-'.")
    if _FORBIDDEN_CHARS_RE.search(hostname):
        raise TargetValidationError("El objetivo contiene caracteres potencialmente peligrosos.")

    lowered = hostname.lower().rstrip(".")
    if lowered in _BLOCKED_HOSTNAMES or lowered.endswith(_BLOCKED_SUFFIXES):
        raise SSRFBlockedError(
            f"Objetivo '{hostname}' bloqueado por política anti-SSRF (nombre reservado o interno).",
            details={"hostname": hostname, "reason": "blocked_internal_hostname"},
        )

    # Check if IP literal
    try:
        ipaddress.ip_address(lowered)
        return
    except ValueError:
        pass

    labels = lowered.split(".")
    if len(labels) < 2:
        raise TargetValidationError(
            "El dominio debe incluir al menos un TLD válido (ej. example.com)."
        )
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            raise TargetValidationError(f"Etiqueta de dominio inválida: '{label}'.")


def parse_and_normalize_target(raw_target: str) -> tuple[TargetType, str, str, str | None, int | None]:
    """Parse and normalize a user-supplied domain, URL, or public IP without resolving DNS."""
    cleaned = raw_target.strip()
    if not cleaned:
        raise TargetValidationError("El objetivo no puede estar vacío.")
    if _FORBIDDEN_CHARS_RE.search(cleaned):
        raise TargetValidationError("El objetivo contiene espacios o caracteres no permitidos.")

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SSRFBlockedError(
                f"Esquema '{scheme}' no permitido. Solo se aceptan http y https.",
                details={"scheme": scheme},
            )
        if parsed.username or parsed.password:
            raise TargetValidationError("No se permiten credenciales embebidas en la URL.")
        if not parsed.hostname:
            raise TargetValidationError("La URL no contiene un hostname válido.")
        hostname = parsed.hostname.lower().rstrip(".")
        _validate_hostname_syntax(hostname)
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            raise TargetValidationError("El puerto especificado está fuera del rango 1-65535.")
        default_port = 443 if scheme == "https" else 80
        try:
            ip_literal = ipaddress.ip_address(hostname)
            formatted_host = f"[{ip_literal}]" if isinstance(ip_literal, ipaddress.IPv6Address) else str(ip_literal)
        except ValueError:
            formatted_host = hostname
        netloc = f"{formatted_host}:{port}" if port and port != default_port else formatted_host
        normalized = f"{scheme}://{netloc}"
        return TargetType.URL, normalized, hostname, scheme, port or default_port

    # Check raw IPv4 / IPv6 literal
    host_only = cleaned.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(host_only)
        normalized_ip = str(ip_obj)
        return TargetType.IP, normalized_ip, normalized_ip, None, None
    except ValueError:
        pass

    # Handle host:port without scheme (reject ambiguous path/query)
    if "/" in cleaned or "?" in cleaned or "#" in cleaned:
        raise TargetValidationError(
            "Para incluir rutas o puertos en un objetivo web, especifica el esquema http:// o https://."
        )

    hostname = cleaned.lower().rstrip(".")
    _validate_hostname_syntax(hostname)
    return TargetType.DOMAIN, hostname, hostname, "https", 443


def resolve_and_validate_ips(hostname: str) -> tuple[str, ...]:
    """Resolve hostname via system DNS and assert ALL returned IPs are publicly routable."""
    try:
        ip_obj = ipaddress.ip_address(hostname)
        ip_str = str(ip_obj)
        if not is_public_routable_ip(ip_str):
            raise SSRFBlockedError(
                f"Dirección IP '{ip_str}' bloqueada por política anti-SSRF (rango privado/reservado).",
                details={"ip": ip_str},
            )
        return (ip_str,)
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetValidationError(
            f"No fue posible resolver el dominio '{hostname}' mediante DNS."
        ) from exc

    unique_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        # Strip IPv6 scope ID if present (e.g. fe80::1%eth0)
        if "%" in ip_str:
            ip_str = ip_str.split("%", 1)[0]
        if ip_str not in unique_ips:
            unique_ips.append(ip_str)

    if not unique_ips:
        raise TargetValidationError(f"DNS no devolvió direcciones IP para '{hostname}'.")

    for ip_str in unique_ips:
        if not is_public_routable_ip(ip_str):
            raise SSRFBlockedError(
                f"El dominio '{hostname}' resuelve a una IP protegida ({ip_str}). Bloqueado por anti-SSRF.",
                details={"hostname": hostname, "blocked_ip": ip_str},
            )

    # Prefer IPv4 first when available for broader Nmap/network reachability
    ipv4_first = sorted(unique_ips, key=lambda addr: 0 if "." in addr else 1)
    return tuple(ipv4_first)


def validate_target_ssrf(raw_target: str) -> ValidatedTarget:
    """Full syntax normalization, DNS resolution, and anti-SSRF enforcement."""
    target_type, normalized, hostname, scheme, port = parse_and_normalize_target(raw_target)
    resolved_ips = resolve_and_validate_ips(hostname)
    return ValidatedTarget(
        target_type=target_type,
        normalized_target=normalized,
        hostname=hostname,
        scheme=scheme,
        port=port,
        resolved_ip=resolved_ips[0],
        resolved_ips=resolved_ips,
    )


def run_safe_command(
    argv: list[str],
    *,
    timeout_seconds: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an external CLI binary safely without a shell (prevents A05:2025 Injection)."""
    if not argv or not isinstance(argv, list):
        raise ValueError("argv must be a non-empty list of strings.")
    for idx, arg in enumerate(argv):
        if not isinstance(arg, str):
            raise ValueError(f"Command argument at index {idx} must be a string.")
        if "\x00" in arg:
            raise TargetValidationError("Null byte detectado en argumento de comando.")

    timeout = timeout_seconds or settings.MAX_SCAN_TIMEOUT_SECONDS
    return subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def safe_http_get(
    url: str,
    *,
    timeout_seconds: float | None = None,
    max_redirects: int = 5,
    verify_tls: bool = True,
    headers: dict[str, str] | None = None,
) -> tuple[SafeHttpResponse, list[str]]:
    """Perform a bounded HTTP GET with SSRF validation on the initial target and every redirect hop."""
    timeout = timeout_seconds or float(settings.HTTP_REQUEST_TIMEOUT_SECONDS)
    request_headers = {
        "User-Agent": "WebSecAuditDashboard/1.0 (+https://owasp.org/Top10/2025/)",
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
        **(headers or {}),
    }

    current_url = url
    visited_chain: list[str] = []

    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout),
        verify=verify_tls,
    ) as client:
        for _hop in range(max_redirects + 1):
            parsed = urlparse(current_url)
            if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                raise SSRFBlockedError(
                    f"Redirección hacia esquema no permitido: '{parsed.scheme}'."
                )
            if not parsed.hostname:
                raise TargetValidationError("URL sin hostname válido durante petición HTTP.")

            _validate_hostname_syntax(parsed.hostname)
            resolve_and_validate_ips(parsed.hostname)

            visited_chain.append(current_url)
            with client.stream("GET", current_url, headers=request_headers) as response:
                if response.is_redirect and "location" in response.headers:
                    location = response.headers["location"].strip()
                    current_url = urljoin(current_url, location)
                    continue

                chunks: list[bytes] = []
                total_bytes = 0
                for chunk in response.iter_bytes():
                    remaining = MAX_SAFE_HTTP_BODY_BYTES - total_bytes
                    if remaining <= 0:
                        break
                    sliced = chunk[:remaining]
                    chunks.append(sliced)
                    total_bytes += len(sliced)

                body = b"".join(chunks)
                charset = response.charset_encoding or "utf-8"
                decoded_text = body.decode(charset, errors="replace")
                set_cookies = tuple(response.headers.get_list("set-cookie"))
                return (
                    SafeHttpResponse(
                        status_code=response.status_code,
                        url=str(response.url),
                        headers=httpx.Headers(response.headers),
                        set_cookies=set_cookies,
                        content=body,
                        text=decoded_text,
                    ),
                    visited_chain,
                )

    raise TargetValidationError(f"Se excedió el límite máximo de {max_redirects} redirecciones.")


def generate_verification_challenge(
    hostname: str,
    method: VerificationMethod,
    scheme: str | None = None,
) -> tuple[str, str]:
    """Generate a cryptographic ownership token and expected verification location."""
    token = f"websec-audit-verify={secrets.token_hex(16)}"
    if method == VerificationMethod.DNS_TXT:
        return token, f"_websec-audit.{hostname}"
    chosen_scheme = scheme if scheme in ALLOWED_SCHEMES else "https"
    return token, f"{chosen_scheme}://{hostname}/.well-known/security-audit.txt"


def check_domain_ownership_dns_txt(hostname: str, expected_token: str) -> tuple[bool, str | None]:
    """Verify domain ownership by querying TXT records at _websec-audit.<hostname>."""
    _validate_hostname_syntax(hostname)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 3.0

    candidates = [f"_websec-audit.{hostname}", hostname]
    last_error = "No se encontró el token esperado en los registros DNS TXT."

    for record_name in candidates:
        try:
            answers = resolver.resolve(record_name, "TXT")
            for rdata in answers:
                txt_value = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ).strip()
                if txt_value == expected_token or expected_token in txt_value:
                    return True, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.DNSException as exc:
            last_error = f"Error consultando DNS TXT para {record_name}: {exc}"

    return False, last_error


def check_domain_ownership_well_known(
    hostname: str,
    expected_token: str,
    preferred_scheme: str | None = None,
    port: int | None = None,
) -> tuple[bool, str | None]:
    """Verify domain ownership via /.well-known/security-audit.txt using SSRF-safe HTTP."""
    _validate_hostname_syntax(hostname)
    resolve_and_validate_ips(hostname)

    schemes = [preferred_scheme] if preferred_scheme in ALLOWED_SCHEMES else ["https", "http"]
    if "http" not in schemes and preferred_scheme == "https":
        schemes.append("http")

    last_error = "No se pudo verificar el archivo /.well-known/security-audit.txt."
    for scheme in schemes:
        port_suffix = ""
        if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            port_suffix = f":{port}"
        target_url = f"{scheme}://{hostname}{port_suffix}/.well-known/security-audit.txt"
        try:
            response, _ = safe_http_get(target_url, timeout_seconds=8.0, verify_tls=(scheme == "https"))
            if response.status_code == 200:
                lines = [line.strip() for line in response.text.splitlines()]
                if expected_token in lines or expected_token in response.text:
                    return True, None
                last_error = f"Archivo encontrado en {target_url}, pero no contiene el token esperado."
            else:
                last_error = f"{target_url} respondió con estado HTTP {response.status_code}."
        except SSRFBlockedError:
            raise
        except Exception as exc:
            last_error = f"Fallo al consultar {target_url}: {exc}"

    return False, last_error
