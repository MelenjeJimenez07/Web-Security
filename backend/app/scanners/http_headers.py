"""Module 2: HTTP Security Headers, Cookie Flags, Error Leaks & Grade Scanner."""

import re
from dataclasses import dataclass
from typing import Any

from app.core.exceptions import ScannerExecutionError, SSRFBlockedError
from app.core.security import safe_http_get
from app.models.enums import SeverityLevel
from app.scanners.base import (
    BaseAuditScanner,
    FindingDraft,
    ModuleScanResult,
    ScanContext,
    score_to_grade,
)


@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    penalty: float
    severity: SeverityLevel
    owasp_code: str
    secondary_codes: tuple[str, ...]
    cwe_id: str
    title: str
    description: str
    remediation: str
    nginx_snippet: str
    apache_snippet: str


_REQUIRED_HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        header="content-security-policy",
        penalty=18.0,
        severity=SeverityLevel.HIGH,
        owasp_code="A05:2025",
        secondary_codes=("A02:2025",),
        cwe_id="CWE-693",
        title="Cabecera Content-Security-Policy (CSP) ausente",
        description=(
            "No se detectó la cabecera Content-Security-Policy. Sin CSP, el navegador no limita "
            "el origen de scripts, estilos ni recursos ejecutables, reduciendo la defensa en "
            "profundidad frente a ataques XSS (A05:2025)."
        ),
        remediation=(
            "Definir una política Content-Security-Policy estricta basada en nonces/hashes o "
            "orígenes explícitos, evitando 'unsafe-inline' y 'unsafe-eval'."
        ),
        nginx_snippet=(
            'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; '
            'object-src \'none\'; frame-ancestors \'none\'; base-uri \'self\';" always;'
        ),
        apache_snippet=(
            'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; '
            'object-src \'none\'; frame-ancestors \'none\'; base-uri \'self\';"'
        ),
    ),
    HeaderRule(
        header="strict-transport-security",
        penalty=15.0,
        severity=SeverityLevel.MEDIUM,
        owasp_code="A02:2025",
        secondary_codes=("A04:2025",),
        cwe_id="CWE-319",
        title="Cabecera Strict-Transport-Security (HSTS) ausente",
        description=(
            "Falta la cabecera HSTS, permitiendo potenciales degradaciones de conexión (SSL "
            "stripping) en primeras peticiones HTTP sin cifrar."
        ),
        remediation="Publicar HSTS con max-age mínimo de 31536000 segundos (1 año) e includeSubDomains.",
        nginx_snippet=(
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
        ),
        apache_snippet=(
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
        ),
    ),
    HeaderRule(
        header="x-frame-options",
        penalty=10.0,
        severity=SeverityLevel.MEDIUM,
        owasp_code="A02:2025",
        secondary_codes=(),
        cwe_id="CWE-1021",
        title="Protección anti-Clickjacking (X-Frame-Options) ausente",
        description=(
            "La respuesta carece de X-Frame-Options (y no se detectó frame-ancestors en CSP), "
            "exponiendo la interfaz a ser incrustada en iframes maliciosos (Clickjacking)."
        ),
        remediation="Configurar X-Frame-Options: DENY (o SAMEORIGIN) y frame-ancestors en CSP.",
        nginx_snippet='add_header X-Frame-Options "DENY" always;',
        apache_snippet='Header always set X-Frame-Options "DENY"',
    ),
    HeaderRule(
        header="x-content-type-options",
        penalty=8.0,
        severity=SeverityLevel.LOW,
        owasp_code="A02:2025",
        secondary_codes=(),
        cwe_id="CWE-16",
        title="Cabecera X-Content-Type-Options: nosniff ausente",
        description=(
            "Sin X-Content-Type-Options: nosniff, algunos navegadores podrían intentar MIME-sniffing "
            "e interpretar contenido estático como ejecutable."
        ),
        remediation="Establecer X-Content-Type-Options con valor exacto 'nosniff'.",
        nginx_snippet='add_header X-Content-Type-Options "nosniff" always;',
        apache_snippet='Header always set X-Content-Type-Options "nosniff"',
    ),
    HeaderRule(
        header="referrer-policy",
        penalty=6.0,
        severity=SeverityLevel.LOW,
        owasp_code="A02:2025",
        secondary_codes=(),
        cwe_id="CWE-200",
        title="Cabecera Referrer-Policy ausente",
        description=(
            "No se especifica Referrer-Policy, lo que puede filtrar URLs o parámetros sensibles en "
            "la cabecera Referer al navegar hacia enlaces externos."
        ),
        remediation="Configurar Referrer-Policy en 'strict-origin-when-cross-origin' o 'no-referrer'.",
        nginx_snippet='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        apache_snippet='Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    ),
    HeaderRule(
        header="permissions-policy",
        penalty=5.0,
        severity=SeverityLevel.LOW,
        owasp_code="A02:2025",
        secondary_codes=(),
        cwe_id="CWE-16",
        title="Cabecera Permissions-Policy ausente",
        description=(
            "La aplicación no restringe explícitamente APIs sensibles del navegador (cámara, "
            "micrófono, geolocalización, pagos) mediante Permissions-Policy."
        ),
        remediation="Definir Permissions-Policy deshabilitando capacidades no requeridas.",
        nginx_snippet=(
            'add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;'
        ),
        apache_snippet=(
            'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"'
        ),
    ),
)

_STACK_TRACE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python Traceback", re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE)),
    ("Werkzeug Debugger", re.compile(r"Werkzeug powered traceback|The debugger caught an exception", re.IGNORECASE)),
    ("Django Debug Page", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>", re.IGNORECASE)),
    ("PHP Fatal / Parse Error", re.compile(r"(Fatal error|Parse error|Warning):.*in\s+/[^\s]+\.php\s+on line\s+\d+", re.IGNORECASE)),
    ("Java Stack Trace", re.compile(r"java\.lang\.\w+Exception:\s+.*\n?\s*at\s+[a-zA-Z0-9_.$]+\(", re.IGNORECASE)),
    ("ASP.NET Exception", re.compile(r"Server Error in '/' Application|System\.Web\.HttpException", re.IGNORECASE)),
    ("SQL Error Leakage", re.compile(r"(SQLSTATE\[|syntax error at or near|mysql_fetch_|ORA-\d{5})", re.IGNORECASE)),
)


def _parse_cookie_attributes(raw_cookie: str) -> dict[str, Any]:
    parts = [segment.strip() for segment in raw_cookie.split(";") if segment.strip()]
    name_val = parts[0] if parts else ""
    cookie_name = name_val.split("=", 1)[0].strip() if "=" in name_val else "(unknown)"

    attrs: dict[str, str | bool] = {}
    for segment in parts[1:]:
        if "=" in segment:
            k, v = segment.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[segment.strip().lower()] = True

    return {
        "name": cookie_name,
        "httponly": bool(attrs.get("httponly", False)),
        "secure": bool(attrs.get("secure", False)),
        "samesite": str(attrs["samesite"]).lower() if "samesite" in attrs else None,
        "raw": raw_cookie,
    }


class HttpHeadersScanner(BaseAuditScanner):
    """Audits defensive HTTP headers, cookie security flags, error leaks, and assigns A+..F grade."""

    module_key = "http_headers"
    module_name = "Auditoría de Cabeceras HTTP, Cookies y Política de Seguridad"
    description = (
        "Evalúa CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, "
        "Permissions-Policy, flags de cookies, exposición de trazas de error y calcula una "
        "calificación de seguridad (A+ a F)."
    )
    is_active = True
    default_owasp_categories = ["A02:2025", "A05:2025", "A07:2025", "A10:2025"]

    def run(self, ctx: ScanContext) -> ModuleScanResult:
        target_url = ctx.build_base_url()
        ctx.log(f"Analizando cabeceras HTTP y cookies en {target_url}...")

        try:
            response, redirect_chain = safe_http_get(target_url, verify_tls=False)
        except SSRFBlockedError:
            raise
        except Exception as exc:
            # Fallback to HTTP if HTTPS connection failed on domain target
            if target_url.startswith("https://") and ctx.scheme in (None, "https"):
                fallback_url = ctx.build_base_url(preferred_scheme="http", port_override=80)
                ctx.log(f"HTTPS no disponible en {target_url}, evaluando {fallback_url}...", level="warning")
                try:
                    response, redirect_chain = safe_http_get(fallback_url, verify_tls=False)
                except Exception as inner_exc:
                    raise ScannerExecutionError(
                        f"No se pudo conectar vía HTTP/HTTPS a {ctx.hostname}: {inner_exc}"
                    ) from inner_exc
            else:
                raise ScannerExecutionError(f"Error en petición HTTP a {target_url}: {exc}") from exc

        findings: list[FindingDraft] = []
        score = 100.0
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # 1. Evaluate HTTP -> HTTPS redirection if applicable
        https_enforced = response.url.startswith("https://")
        score -= self._check_https_enforcement(ctx, https_enforced, findings)

        # 2. Evaluate defensive headers
        header_audit: dict[str, Any] = {}
        csp_value = headers_lower.get("content-security-policy", "")
        has_csp_frame_ancestors = "frame-ancestors" in csp_value.lower()

        for rule in _REQUIRED_HEADER_RULES:
            val = headers_lower.get(rule.header)
            if rule.header == "x-frame-options" and not val and has_csp_frame_ancestors:
                header_audit[rule.header] = {"present": True, "via": "csp_frame_ancestors"}
                continue

            if not val:
                score -= rule.penalty
                header_audit[rule.header] = {"present": False, "value": None}
                findings.append(
                    FindingDraft(
                        title=rule.title,
                        technical_description=rule.description,
                        severity=rule.severity,
                        owasp_category_code=rule.owasp_code,
                        secondary_owasp_codes=list(rule.secondary_codes),
                        affected_component=response.url,
                        cwe_id=rule.cwe_id,
                        evidence={"url": response.url, "missing_header": rule.header},
                        remediation_steps=rule.remediation,
                        remediation_snippets={
                            "nginx": rule.nginx_snippet,
                            "apache": rule.apache_snippet,
                        },
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )
            else:
                header_audit[rule.header] = {"present": True, "value": val}
                score -= self._evaluate_weak_header_value(rule.header, val, response.url, findings)

        # 3. Server/Technology info disclosure headers + permissive CORS
        score -= self._check_disclosure_and_cors(headers_lower, response.url, findings)

        # 4. Cookie security flags
        parsed_cookies = [_parse_cookie_attributes(raw) for raw in response.set_cookies]
        score -= self._check_cookies(parsed_cookies, response.url, findings)

        # 5. Accidental stack trace / debug mode leak detection (A10:2025)
        leaks = self._check_error_leakage(ctx, response.url, response.text, findings)
        if leaks:
            score -= 15.0

        # 6. Passive inspection of standard discovery files (robots.txt & sitemap.xml)
        discovery_files = self._check_discovery_files(ctx, findings)

        final_score = max(0.0, round(score, 1))
        grade = score_to_grade(final_score)

        ctx.log(
            f"Calificación de seguridad HTTP calculada: {grade} ({final_score}/100).",
            level="info",
            data={"grade": grade, "score": final_score, "cookies_count": len(parsed_cookies)},
        )

        return ModuleScanResult(
            module_key=self.module_key,
            module_name=self.module_name,
            findings=findings,
            raw_output={
                "final_url": response.url,
                "status_code": response.status_code,
                "redirect_chain": redirect_chain,
                "https_enforced": https_enforced,
                "grade": grade,
                "score": final_score,
                "headers_audit": header_audit,
                "cookies": [
                    {k: v for k, v in c.items() if k != "raw"} for c in parsed_cookies
                ],
                "error_leaks_detected": leaks,
                "discovery_files": discovery_files,
            },
            summary_metrics={
                "http_grade": grade,
                "http_score": final_score,
                "cookies_analyzed": len(parsed_cookies),
                "robots_txt_present": discovery_files["robots_txt"]["present"],
                "sitemap_xml_present": discovery_files["sitemap_xml"]["present"],
            },
        )

    def _check_https_enforcement(
        self, ctx: ScanContext, final_is_https: bool, findings: list[FindingDraft]
    ) -> float:
        if not final_is_https:
            findings.append(
                FindingDraft(
                    title="Sitio servido sin cifrado HTTPS obligatorio",
                    technical_description=(
                        "El destino respondió sobre HTTP sin redirección automática a HTTPS, "
                        "exponiendo tráfico, cabeceras y credenciales a interceptación."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    secondary_owasp_codes=["A02:2025"],
                    affected_component=ctx.build_base_url(preferred_scheme="http", port_override=80),
                    cwe_id="CWE-319",
                    remediation_steps="Configurar redirección permanente 301 desde HTTP (80) hacia HTTPS (443).",
                    remediation_snippets={
                        "nginx": "return 301 https://$host$request_uri;",
                        "apache": "Redirect permanent / https://example.com/",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
            return 15.0

        http_url = ctx.build_base_url(preferred_scheme="http", port_override=80)
        try:
            http_resp, _ = safe_http_get(http_url, timeout_seconds=5.0, max_redirects=3, verify_tls=False)
            if not http_resp.url.startswith("https://"):
                findings.append(
                    FindingDraft(
                        title="Puerto HTTP (80) no redirige automáticamente a HTTPS",
                        technical_description=(
                            f"La petición a {http_url} permaneció en HTTP ({http_resp.status_code}) "
                            "en lugar de redirigir al canal cifrado HTTPS."
                        ),
                        severity=SeverityLevel.MEDIUM,
                        owasp_category_code="A02:2025",
                        secondary_owasp_codes=["A04:2025"],
                        affected_component=http_url,
                        cwe_id="CWE-319",
                        remediation_steps="Forzar redirección HTTP 301 -> HTTPS en el VirtualHost del puerto 80.",
                        remediation_snippets={
                            "nginx": "server {\n    listen 80;\n    return 301 https://$host$request_uri;\n}",
                            "apache": "<VirtualHost *:80>\n    Redirect permanent / https://%{HTTP_HOST}/\n</VirtualHost>",
                        },
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )
                return 8.0
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        return 0.0

    def _evaluate_weak_header_value(
        self, header: str, value: str, url: str, findings: list[FindingDraft]
    ) -> float:
        lower = value.lower()
        if header == "content-security-policy" and (
            "'unsafe-inline'" in lower or "'unsafe-eval'" in lower
        ):
            findings.append(
                FindingDraft(
                    title="Política Content-Security-Policy (CSP) permisiva ('unsafe-inline' / 'unsafe-eval')",
                    technical_description=(
                        f"La cabecera CSP incluye directivas inseguras ({value[:240]}), lo que "
                        "debilita significativamente la mitigación frente a XSS."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A05:2025",
                    secondary_owasp_codes=["A02:2025"],
                    affected_component=url,
                    cwe_id="CWE-693",
                    evidence={"content_security_policy": value},
                    remediation_steps="Eliminar 'unsafe-inline' y 'unsafe-eval' sustituyéndolos por nonces o hashes SHA-256.",
                    remediation_snippets={
                        "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
                        "apache": 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
            return 7.0

        if header == "strict-transport-security":
            match = re.search(r"max-age=(\d+)", lower)
            max_age = int(match.group(1)) if match else 0
            if max_age < 31536000:
                findings.append(
                    FindingDraft(
                        title="HSTS configurado con max-age inferior a 1 año",
                        technical_description=(
                            f"El valor actual de HSTS tiene max-age={max_age}s (< 31536000s recomendados)."
                        ),
                        severity=SeverityLevel.LOW,
                        owasp_category_code="A02:2025",
                        secondary_owasp_codes=["A04:2025"],
                        affected_component=url,
                        cwe_id="CWE-319",
                        evidence={"strict_transport_security": value},
                        remediation_steps="Incrementar max-age al menos a 31536000 segundos.",
                        remediation_snippets={
                            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                        },
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )
                return 4.0
        return 0.0

    def _check_disclosure_and_cors(
        self, headers_lower: dict[str, str], url: str, findings: list[FindingDraft]
    ) -> float:
        penalty = 0.0
        disclosed = {
            h: headers_lower[h]
            for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
            if h in headers_lower and any(ch.isdigit() for ch in headers_lower[h])
        }
        if disclosed:
            penalty += 5.0
            findings.append(
                FindingDraft(
                    title="Divulgación de versiones de servidor o runtime en cabeceras HTTP",
                    technical_description=(
                        "Las cabeceras de respuesta revelan identificadores y versiones específicas "
                        f"de software ({disclosed})."
                    ),
                    severity=SeverityLevel.LOW,
                    owasp_category_code="A02:2025",
                    affected_component=url,
                    cwe_id="CWE-200",
                    evidence={"disclosed_headers": disclosed},
                    remediation_steps="Ocultar cabeceras X-Powered-By y suprimir versión en Server.",
                    remediation_snippets={
                        "nginx": "server_tokens off;\nproxy_hide_header X-Powered-By;",
                        "apache": "ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        acao = headers_lower.get("access-control-allow-origin", "").strip()
        acac = headers_lower.get("access-control-allow-credentials", "").strip().lower()
        if acao == "*" and acac == "true":
            penalty += 12.0
            findings.append(
                FindingDraft(
                    title="Política CORS insegura (wildcard '*' con Allow-Credentials: true)",
                    technical_description=(
                        "Se detectó Access-Control-Allow-Origin: * combinado con credenciales habilitadas."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A01:2025",
                    secondary_owasp_codes=["A02:2025"],
                    affected_component=url,
                    cwe_id="CWE-942",
                    evidence={"acao": acao, "acac": acac},
                    remediation_steps="Sustituir el wildcard '*' por una lista blanca estricta de orígenes confiables.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
        return penalty

    def _check_cookies(
        self, cookies: list[dict[str, Any]], url: str, findings: list[FindingDraft]
    ) -> float:
        if not cookies:
            return 0.0

        penalty = 0.0
        for cookie in cookies:
            missing_flags: list[str] = []
            if not cookie["httponly"]:
                missing_flags.append("HttpOnly")
            if not cookie["secure"]:
                missing_flags.append("Secure")
            if not cookie["samesite"]:
                missing_flags.append("SameSite")

            if missing_flags:
                penalty = min(penalty + 8.0, 20.0)
                severity = (
                    SeverityLevel.HIGH
                    if ("HttpOnly" in missing_flags and "Secure" in missing_flags)
                    else SeverityLevel.MEDIUM
                )
                findings.append(
                    FindingDraft(
                        title=f"Cookie '{cookie['name']}' sin flags de seguridad: {', '.join(missing_flags)}",
                        technical_description=(
                            f"La cookie '{cookie['name']}' carece de los atributos {', '.join(missing_flags)}, "
                            "incrementando el riesgo de robo de sesión vía XSS, transmisión en claro o CSRF."
                        ),
                        severity=severity,
                        owasp_category_code="A07:2025",
                        secondary_owasp_codes=["A02:2025"],
                        affected_component=f"Cookie: {cookie['name']} ({url})",
                        cwe_id="CWE-614" if "Secure" in missing_flags else "CWE-1004",
                        evidence={
                            "cookie_name": cookie["name"],
                            "httponly": cookie["httponly"],
                            "secure": cookie["secure"],
                            "samesite": cookie["samesite"],
                        },
                        remediation_steps=(
                            "Configurar todas las cookies de sesión con Secure, HttpOnly y SameSite=Lax (o Strict)."
                        ),
                        remediation_snippets={
                            "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
                            "apache": 'Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"',
                        },
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )
        return penalty

    def _check_error_leakage(
        self,
        ctx: ScanContext,
        main_url: str,
        main_body: str,
        findings: list[FindingDraft],
    ) -> list[str]:
        bodies_to_inspect = [(main_url, main_body)]
        probe_404_url = f"{ctx.build_base_url()}/websec-audit-nonexistent-404-probe"
        try:
            resp_404, _ = safe_http_get(probe_404_url, timeout_seconds=6.0, verify_tls=False)
            bodies_to_inspect.append((resp_404.url, resp_404.text))
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        matched_signatures: list[str] = []
        matched_urls: list[str] = []
        for checked_url, body in bodies_to_inspect:
            snippet = body[:65536]
            for sig_name, pattern in _STACK_TRACE_PATTERNS:
                if pattern.search(snippet) and sig_name not in matched_signatures:
                    matched_signatures.append(sig_name)
                    if checked_url not in matched_urls:
                        matched_urls.append(checked_url)

        if matched_signatures:
            findings.append(
                FindingDraft(
                    title="Exposición de stack traces o mensajes de depuración internos",
                    technical_description=(
                        "La aplicación devolvió trazas de error detalladas "
                        f"({', '.join(matched_signatures)}), revelando rutas internas, framework "
                        "o detalles de excepciones no controladas."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A10:2025",
                    secondary_owasp_codes=["A02:2025"],
                    affected_component=", ".join(matched_urls),
                    cwe_id="CWE-209",
                    evidence={"matched_signatures": matched_signatures, "urls": matched_urls},
                    remediation_steps=(
                        "Desactivar DEBUG en producción y configurar páginas/manejadores globales de "
                        "error que devuelvan respuestas genéricas sin trazas internas."
                    ),
                    remediation_snippets={
                        "nginx": "proxy_intercept_errors on;\nerror_page 404 500 502 503 504 /error_generic.html;",
                        "apache": "ErrorDocument 500 /error_generic.html\nErrorDocument 404 /error_generic.html",
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
        return matched_signatures

    def _check_discovery_files(
        self,
        ctx: ScanContext,
        findings: list[FindingDraft],
    ) -> dict[str, Any]:
        """Passively inspect standard /robots.txt and /sitemap.xml without wordlist fuzzing."""
        base_url = ctx.build_base_url()
        sensitive_keywords = (
            "/admin",
            "/panel",
            "/backup",
            "/config",
            "/private",
            "/internal",
            "/debug",
            "/swagger",
            "/api-docs",
            "/.git",
            "/.env",
            "/db",
            "/phpinfo",
            "/console",
            "/staging",
        )

        robots_info: dict[str, Any] = {
            "url": f"{base_url}/robots.txt",
            "present": False,
            "status_code": None,
            "disallow_paths": [],
            "sensitive_disallows": [],
            "sitemaps": [],
        }
        try:
            robots_resp, _ = safe_http_get(
                robots_resp_url := f"{base_url}/robots.txt",
                timeout_seconds=5.0,
                verify_tls=False,
            )
            robots_info["url"] = robots_resp.url or robots_resp_url
            robots_info["status_code"] = robots_resp.status_code
            ctype = robots_resp.headers.get("content-type", "").lower()
            sample = robots_resp.text[:32768]
            if robots_resp.status_code == 200 and "<html" not in sample[:512].lower() and "html" not in ctype:
                disallows: list[str] = []
                sensitive_hits: list[str] = []
                declared_sitemaps: list[str] = []
                for raw_line in sample.splitlines():
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    lower_line = line.lower()
                    if lower_line.startswith("disallow:"):
                        path_val = line.split(":", 1)[1].strip()
                        if path_val and path_val not in disallows:
                            disallows.append(path_val)
                            if any(kw in path_val.lower() for kw in sensitive_keywords):
                                sensitive_hits.append(path_val)
                    elif lower_line.startswith("sitemap:"):
                        sm_val = line.split(":", 1)[1].strip()
                        if sm_val and sm_val not in declared_sitemaps:
                            declared_sitemaps.append(sm_val)

                if disallows or declared_sitemaps or "user-agent:" in sample.lower():
                    robots_info["present"] = True
                    robots_info["disallow_paths"] = disallows[:50]
                    robots_info["sensitive_disallows"] = sensitive_hits[:25]
                    robots_info["sitemaps"] = declared_sitemaps[:10]

                if sensitive_hits:
                    ctx.log(
                        f"robots.txt declara {len(sensitive_hits)} ruta(s) potencialmente sensible(s).",
                        level="warning",
                        data={"sensitive_disallows": sensitive_hits[:10]},
                    )
                    findings.append(
                        FindingDraft(
                            title=f"Rutas administrativas o sensibles declaradas en robots.txt ({len(sensitive_hits)})",
                            technical_description=(
                                f"El archivo público {robots_info['url']} contiene directivas Disallow "
                                f"que referencian rutas potencialmente sensibles: {', '.join(sensitive_hits[:10])}. "
                                "robots.txt es de acceso público y no restringe el acceso real."
                            ),
                            severity=SeverityLevel.LOW,
                            owasp_category_code="A02:2025",
                            secondary_owasp_codes=["A01:2025"],
                            affected_component=robots_info["url"],
                            cwe_id="CWE-200",
                            evidence={
                                "robots_url": robots_info["url"],
                                "sensitive_disallows": sensitive_hits[:25],
                                "total_disallows": len(disallows),
                            },
                            remediation_steps=(
                                "No depender de robots.txt para ocultar paneles o recursos privados; aplicar "
                                "autenticación robusta y control de acceso explícito en el servidor."
                            ),
                            references=["https://owasp.org/Top10/2025/"],
                        )
                    )
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        sitemap_info: dict[str, Any] = {
            "url": f"{base_url}/sitemap.xml",
            "present": False,
            "status_code": None,
            "url_count": 0,
        }
        try:
            sm_resp, _ = safe_http_get(
                f"{base_url}/sitemap.xml",
                timeout_seconds=5.0,
                verify_tls=False,
            )
            sitemap_info["url"] = sm_resp.url
            sitemap_info["status_code"] = sm_resp.status_code
            sm_sample = sm_resp.text[:131072]
            if sm_resp.status_code == 200 and ("<urlset" in sm_sample.lower() or "<sitemapindex" in sm_sample.lower()):
                sitemap_info["present"] = True
                sitemap_info["url_count"] = len(re.findall(r"<loc>", sm_sample, re.IGNORECASE))
                ctx.log(
                    f"sitemap.xml accesible con {sitemap_info['url_count']} URL(s) listadas.",
                    level="info",
                )
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        return {"robots_txt": robots_info, "sitemap_xml": sitemap_info}
