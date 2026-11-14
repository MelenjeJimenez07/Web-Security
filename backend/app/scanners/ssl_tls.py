"""Module 3: SSL/TLS Cryptographic Configuration and X.509 Certificate Analyzer."""

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from app.core.exceptions import ScannerExecutionError, SSRFBlockedError
from app.core.security import is_ip_allowed_for_scan
from app.models.enums import SeverityLevel, TargetType
from app.scanners.base import BaseAuditScanner, FindingDraft, ModuleScanResult, ScanContext

_TLS_PROBES: tuple[tuple[str, ssl.TLSVersion, bool], ...] = (
    ("TLSv1.0", ssl.TLSVersion.TLSv1, True),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, False),
)

_WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ADH", "AECDH", "EXP")


class SslTlsScanner(BaseAuditScanner):
    """Inspects X.509 certificate trust/expiry, TLS protocol versions, and cipher suites."""

    module_key = "ssl_tls"
    module_name = "Análisis Criptográfico SSL/TLS"
    description = (
        "Inspecciona validez del certificado X.509, cadena de confianza, fortaleza de clave, "
        "versiones de protocolo (TLS 1.0–1.3) y suites de cifrado soportadas."
    )
    is_active = True
    default_owasp_categories = ["A04:2025"]

    def run(self, ctx: ScanContext) -> ModuleScanResult:
        if not is_ip_allowed_for_scan(ctx.hostname, ctx.resolved_ip):
            raise SSRFBlockedError(
                f"IP '{ctx.resolved_ip}' bloqueada antes de inspección SSL/TLS."
            )

        tls_port = ctx.port if (ctx.scheme == "https" and ctx.port) else 443
        if ctx.scheme == "http" and ctx.port == 80:
            tls_port = 443

        sni_host = None if ctx.target_type == TargetType.IP else ctx.hostname
        ctx.log(f"Inspeccionando certificado y protocolos TLS en {ctx.resolved_ip}:{tls_port}...")

        findings: list[FindingDraft] = []
        target_label = f"{ctx.hostname}:{tls_port}"

        # 1. Verify CA trust chain and hostname match
        chain_trusted, trust_error = self._check_trust_chain(
            ctx.resolved_ip, tls_port, sni_host
        )

        # 2. Retrieve raw DER certificate and negotiated parameters
        try:
            der_cert, negotiated_proto, negotiated_cipher = self._fetch_cert_and_cipher(
                ctx.resolved_ip, tls_port, sni_host
            )
        except Exception as exc:
            if ctx.scheme == "http":
                return ModuleScanResult(
                    module_key=self.module_key,
                    module_name=self.module_name,
                    findings=[
                        FindingDraft(
                            title="Servicio HTTPS/TLS no disponible en puerto 443",
                            technical_description=(
                                f"No fue posible establecer una sesión TLS en {target_label}: {exc}"
                            ),
                            severity=SeverityLevel.HIGH,
                            owasp_category_code="A04:2025",
                            affected_component=target_label,
                            cwe_id="CWE-319",
                            remediation_steps="Habilitar TLS 1.2/1.3 con un certificado X.509 válido en el puerto 443.",
                            references=["https://owasp.org/Top10/2025/"],
                        )
                    ],
                    raw_output={"tls_available": False, "error": str(exc)},
                    summary_metrics={"tls_available": False},
                )
            raise ScannerExecutionError(
                f"No se pudo completar el handshake SSL/TLS en {target_label}: {exc}"
            ) from exc

        cert_info = self._analyze_certificate(der_cert, chain_trusted, trust_error, target_label, findings)

        # 3. Probe supported TLS protocol versions
        supported_protocols = self._probe_tls_protocols(ctx.resolved_ip, tls_port, sni_host)
        self._evaluate_protocols_and_cipher(
            supported_protocols, negotiated_cipher, target_label, findings
        )

        ctx.log(
            f"Análisis TLS finalizado. Protocolos soportados: {', '.join(supported_protocols) or 'N/A'}",
            level="info",
            data={"supported_protocols": supported_protocols, "cipher": negotiated_cipher},
        )

        return ModuleScanResult(
            module_key=self.module_key,
            module_name=self.module_name,
            findings=findings,
            raw_output={
                "tls_available": True,
                "port": tls_port,
                "chain_trusted": chain_trusted,
                "trust_error": trust_error,
                "negotiated_protocol": negotiated_proto,
                "negotiated_cipher": negotiated_cipher,
                "supported_protocols": supported_protocols,
                "certificate": cert_info,
            },
            summary_metrics={
                "tls_available": True,
                "chain_trusted": chain_trusted,
                "supported_protocols": supported_protocols,
                "cert_days_remaining": cert_info.get("days_remaining"),
            },
        )

    def _check_trust_chain(
        self, target_ip: str, port: int, sni_host: str | None
    ) -> tuple[bool, str | None]:
        context = ssl.create_default_context()
        context.check_hostname = sni_host is not None
        try:
            with socket.create_connection((target_ip, port), timeout=8.0) as sock:
                with context.wrap_socket(sock, server_hostname=sni_host):
                    return True, None
        except ssl.SSLCertVerificationError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)

    def _fetch_cert_and_cipher(
        self, target_ip: str, port: int, sni_host: str | None
    ) -> tuple[bytes, str | None, dict[str, Any]]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, port), timeout=8.0) as sock:
            with context.wrap_socket(sock, server_hostname=sni_host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ValueError("El servidor no presentó un certificado X.509.")
                cipher_tuple = ssock.cipher()
                cipher_info = {
                    "name": cipher_tuple[0] if cipher_tuple else None,
                    "protocol": cipher_tuple[1] if cipher_tuple else None,
                    "bits": cipher_tuple[2] if cipher_tuple else None,
                }
                return der_cert, ssock.version(), cipher_info

    def _analyze_certificate(
        self,
        der_cert: bytes,
        chain_trusted: bool,
        trust_error: str | None,
        target_label: str,
        findings: list[FindingDraft],
    ) -> dict[str, Any]:
        cert = x509.load_der_x509_certificate(der_cert)
        now = datetime.now(UTC)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_remaining = (not_after - now).days

        pub_key = cert.public_key()
        key_type = type(pub_key).__name__
        key_size: int | None = None
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA ({pub_key.curve.name})"
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size

        sig_hash = (
            cert.signature_hash_algorithm.name.upper()
            if cert.signature_hash_algorithm
            else "UNKNOWN"
        )

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        cert_summary = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": hex(cert.serial_number),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "key_type": key_type,
            "key_size": key_size,
            "signature_hash": sig_hash,
            "san_dns_names": sans[:25],
        }

        if not chain_trusted:
            findings.append(
                FindingDraft(
                    title="Certificado SSL/TLS no confiable, autofirmado o con hostname inválido",
                    technical_description=(
                        f"La validación de cadena de confianza y nombre de host falló: {trust_error}"
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-295",
                    evidence={"trust_error": trust_error, "certificate": cert_summary},
                    remediation_steps=(
                        "Instalar un certificado emitido por una Autoridad Certificadora (CA) "
                        "confiable incluyendo la cadena intermedia completa y los SAN correctos."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        if days_remaining < 0:
            findings.append(
                FindingDraft(
                    title="Certificado SSL/TLS expirado",
                    technical_description=(
                        f"El certificado caducó el {not_after.isoformat()} (hace {abs(days_remaining)} días)."
                    ),
                    severity=SeverityLevel.CRITICAL,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-298",
                    evidence=cert_summary,
                    remediation_steps="Renovar e instalar inmediatamente el certificado TLS.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
        elif days_remaining <= 30:
            findings.append(
                FindingDraft(
                    title=f"Certificado SSL/TLS próximo a expirar ({days_remaining} días restantes)",
                    technical_description=f"El certificado expirará el {not_after.isoformat()}.",
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-298",
                    evidence=cert_summary,
                    remediation_steps="Automatizar la renovación mediante ACME/Certbot antes del vencimiento.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        if (isinstance(pub_key, rsa.RSAPublicKey) and (key_size or 0) < 2048) or (
            isinstance(pub_key, ec.EllipticCurvePublicKey) and (key_size or 0) < 256
        ):
            findings.append(
                FindingDraft(
                    title=f"Longitud de clave criptográfica débil ({key_type} {key_size} bits)",
                    technical_description="La clave pública del certificado es inferior al mínimo recomendado (RSA >= 2048 / ECDSA >= 256).",
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-326",
                    evidence=cert_summary,
                    remediation_steps="Emitir un nuevo certificado con clave RSA >= 2048 bits o ECDSA P-256.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        if isinstance(cert.signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):
            findings.append(
                FindingDraft(
                    title=f"Algoritmo de firma de certificado obsoleto ({sig_hash})",
                    technical_description=f"El certificado utiliza firma criptográfica débil ({sig_hash}).",
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-328",
                    evidence=cert_summary,
                    remediation_steps="Reemplazar el certificado por uno firmado con SHA-256 o superior.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        return cert_summary

    def _probe_tls_protocols(
        self, target_ip: str, port: int, sni_host: str | None
    ) -> list[str]:
        supported: list[str] = []
        for label, version, is_legacy in _TLS_PROBES:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                if is_legacy:
                    context.set_ciphers("ALL:@SECLEVEL=0")
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((target_ip, port), timeout=5.0) as sock:
                    with context.wrap_socket(sock, server_hostname=sni_host):
                        supported.append(label)
            except (ssl.SSLError, ValueError, OSError):
                continue
        return supported

    def _evaluate_protocols_and_cipher(
        self,
        supported_protocols: list[str],
        negotiated_cipher: dict[str, Any],
        target_label: str,
        findings: list[FindingDraft],
    ) -> None:
        deprecated = [p for p in supported_protocols if p in ("TLSv1.0", "TLSv1.1")]
        if deprecated:
            findings.append(
                FindingDraft(
                    title=f"Protocolos TLS obsoletos habilitados: {', '.join(deprecated)}",
                    technical_description=(
                        f"El servidor acepta negociaciones con versiones deprecadas ({', '.join(deprecated)}), "
                        "vulnerables a ataques conocidos de degradación y relleno."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    secondary_owasp_codes=["A02:2025"],
                    affected_component=target_label,
                    cwe_id="CWE-327",
                    evidence={"supported_protocols": supported_protocols},
                    remediation_steps="Deshabilitar TLS 1.0 y TLS 1.1; permitir únicamente TLSv1.2 y TLSv1.3.",
                    remediation_snippets={
                        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;",
                        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        if supported_protocols and "TLSv1.3" not in supported_protocols:
            findings.append(
                FindingDraft(
                    title="TLS 1.3 no soportado",
                    technical_description=(
                        "El servidor no negoció TLS 1.3, perdiendo mejoras de latencia, Forward "
                        "Secrecy obligatorio y eliminación de suites heredadas."
                    ),
                    severity=SeverityLevel.LOW,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-326",
                    evidence={"supported_protocols": supported_protocols},
                    remediation_steps="Habilitar TLSv1.3 junto a TLSv1.2 en la configuración del servidor.",
                    remediation_snippets={
                        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        cipher_name = (negotiated_cipher.get("name") or "").upper()
        if cipher_name and any(tok in cipher_name for tok in _WEAK_CIPHER_TOKENS):
            findings.append(
                FindingDraft(
                    title=f"Suite de cifrado débil negociada ({cipher_name})",
                    technical_description=(
                        f"La conexión negoció la suite {cipher_name}, considerada criptográficamente débil."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    affected_component=target_label,
                    cwe_id="CWE-327",
                    evidence={"negotiated_cipher": negotiated_cipher},
                    remediation_steps="Restringir suites a AEAD modernas con ECDHE (AES-GCM / ChaCha20-Poly1305).",
                    remediation_snippets={
                        "nginx": "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';",
                        "apache": "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
