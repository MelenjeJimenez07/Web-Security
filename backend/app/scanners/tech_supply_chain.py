"""Module 5: Technology Fingerprinting, SRI Verification & Passive NVD CVE Lookup."""

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import redis
from bs4 import BeautifulSoup

from app.core.config import get_settings
from app.core.exceptions import SSRFBlockedError
from app.core.security import safe_http_get
from app.models.enums import SeverityLevel
from app.scanners.base import BaseAuditScanner, FindingDraft, ModuleScanResult, ScanContext

settings = get_settings()

# (display_name, nvd_keyword, regex_pattern)
_HEADER_TECH_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("Nginx", "nginx", re.compile(r"nginx(?:/(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("Apache HTTP Server", "apache http server", re.compile(r"Apache(?:/(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("Microsoft IIS", "microsoft iis", re.compile(r"Microsoft-IIS(?:/(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("PHP", "php", re.compile(r"PHP(?:/(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("Express", "express", re.compile(r"\bExpress\b", re.IGNORECASE)),
    ("Cloudflare", "cloudflare", re.compile(r"\bcloudflare\b", re.IGNORECASE)),
    ("OpenResty", "openresty", re.compile(r"openresty(?:/(\d+(?:\.\d+)+))?", re.IGNORECASE)),
)

_HTML_TECH_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("WordPress", "wordpress", re.compile(r"WordPress(?:\s+|/)(\d+(?:\.\d+)+)?|wp-content/", re.IGNORECASE)),
    ("Drupal", "drupal", re.compile(r"Drupal(?:\s+(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("Joomla", "joomla", re.compile(r"Joomla!?(?:\s+(\d+(?:\.\d+)+))?", re.IGNORECASE)),
    ("jQuery", "jquery", re.compile(r"jquery[.-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("Bootstrap", "bootstrap", re.compile(r"bootstrap[.-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("Lodash", "lodash", re.compile(r"lodash[.-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("React", "react", re.compile(r"react(?:\.production\.min)?\.js|__REACT_DEVTOOLS|data-reactroot", re.IGNORECASE)),
    ("Next.js", "next.js", re.compile(r"/_next/static/|__NEXT_DATA__", re.IGNORECASE)),
    ("Angular", "angular", re.compile(r"ng-version=\"(\d+(?:\.\d+)+)\"", re.IGNORECASE)),
    ("Vue.js", "vue", re.compile(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|data-v-", re.IGNORECASE)),
)


class TechSupplyChainScanner(BaseAuditScanner):
    """Identifies software stack, checks external script SRI, and queries NVD for known CVEs."""

    module_key = "tech_supply_chain"
    module_name = "Fingerprinting de Tecnologías y Cadena de Suministro"
    description = (
        "Identifica servidores web, frameworks, CMS y librerías JS expuestas; valida Subresource "
        "Integrity (SRI) en scripts externos y consulta CVEs conocidos en NVD de forma pasiva."
    )
    is_active = True
    default_owasp_categories = ["A03:2025", "A08:2025"]

    def run(self, ctx: ScanContext) -> ModuleScanResult:
        target_url = ctx.build_base_url()
        ctx.log(f"Analizando stack tecnológico y recursos externos en {target_url}...")

        try:
            response, _ = safe_http_get(target_url, verify_tls=False)
        except SSRFBlockedError:
            raise
        except Exception as exc:
            if target_url.startswith("https://") and ctx.scheme in (None, "https"):
                fallback_url = ctx.build_base_url(preferred_scheme="http", port_override=80)
                try:
                    response, _ = safe_http_get(fallback_url, verify_tls=False)
                except Exception as inner_exc:
                    return ModuleScanResult(
                        module_key=self.module_key,
                        module_name=self.module_name,
                        skipped_reason=f"Objetivo web inaccesible para fingerprinting: {inner_exc}",
                        raw_output={"skipped": True, "error": str(inner_exc)},
                    )
            else:
                return ModuleScanResult(
                    module_key=self.module_key,
                    module_name=self.module_name,
                    skipped_reason=f"Objetivo web inaccesible para fingerprinting: {exc}",
                    raw_output={"skipped": True, "error": str(exc)},
                )

        technologies = self._fingerprint_technologies(response.headers, response.text)
        findings: list[FindingDraft] = []

        # 1. Subresource Integrity (SRI) & mixed content check on external scripts/styles
        external_assets = self._audit_external_resources(
            response.url, response.text, ctx.hostname, findings
        )

        # 2. Passive CVE lookup via NVD API 2.0 for technologies with detected version
        cve_matches = self._lookup_nvd_cves(ctx, technologies, response.url, findings)

        if technologies:
            findings.append(
                FindingDraft(
                    title=f"Inventario tecnológico detectado ({len(technologies)} componente(s))",
                    technical_description=(
                        "Se identificaron los siguientes componentes mediante análisis pasivo de "
                        f"cabeceras y DOM: {', '.join(t['label'] for t in technologies)}."
                    ),
                    severity=SeverityLevel.INFO,
                    owasp_category_code="A03:2025",
                    affected_component=response.url,
                    cwe_id="CWE-1104",
                    evidence={"technologies": technologies},
                    remediation_steps=(
                        "Mantener un inventario SBOM actualizado, aplicar parches de seguridad "
                        "periódicamente y evitar exponer versiones exactas en cabeceras públicas."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        return ModuleScanResult(
            module_key=self.module_key,
            module_name=self.module_name,
            findings=findings,
            raw_output={
                "analyzed_url": response.url,
                "technologies": technologies,
                "external_resources": external_assets,
                "cve_matches": cve_matches,
            },
            summary_metrics={
                "technologies_count": len(technologies),
                "external_resources_count": len(external_assets),
                "sri_missing_count": sum(1 for r in external_assets if not r["has_sri"]),
                "cves_matched": sum(len(m["cves"]) for m in cve_matches),
            },
        )

    def _fingerprint_technologies(
        self, headers: httpx.Headers, html_body: str
    ) -> list[dict[str, Any]]:
        detected: dict[str, dict[str, Any]] = {}

        header_text = " | ".join(
            headers.get(h, "") for h in ("server", "x-powered-by", "x-generator", "via")
        )
        for name, nvd_kw, pattern in _HEADER_TECH_PATTERNS:
            match = pattern.search(header_text)
            if match:
                version = match.group(1) if match.lastindex else None
                detected[name] = {
                    "name": name,
                    "nvd_keyword": nvd_kw,
                    "version": version,
                    "label": f"{name} {version}".strip() if version else name,
                    "source": "http_headers",
                }

        soup = BeautifulSoup(html_body[:300000], "lxml")
        meta_gen = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.IGNORECASE)})
        meta_content = str(meta_gen.get("content", "")) if meta_gen else ""
        script_srcs = " ".join(
            str(tag.get("src", "")) for tag in soup.find_all("script", src=True)
        )
        link_hrefs = " ".join(
            str(tag.get("href", "")) for tag in soup.find_all("link", href=True)
        )
        dom_corpus = f"{meta_content}\n{script_srcs}\n{link_hrefs}\n{html_body[:80000]}"

        for name, nvd_kw, pattern in _HTML_TECH_PATTERNS:
            match = pattern.search(dom_corpus)
            if match:
                version = (
                    match.group(1)
                    if (match.lastindex and match.group(1))
                    else None
                )
                existing = detected.get(name)
                if not existing or (version and not existing.get("version")):
                    detected[name] = {
                        "name": name,
                        "nvd_keyword": nvd_kw,
                        "version": version,
                        "label": f"{name} {version}".strip() if version else name,
                        "source": "html_dom",
                    }

        return list(detected.values())

    def _audit_external_resources(
        self,
        page_url: str,
        html_body: str,
        target_hostname: str,
        findings: list[FindingDraft],
    ) -> list[dict[str, Any]]:
        soup = BeautifulSoup(html_body[:300000], "lxml")
        external_resources: list[dict[str, Any]] = []
        missing_sri_scripts: list[str] = []
        mixed_content_urls: list[str] = []
        is_https_page = page_url.startswith("https://")

        tags: list[tuple[str, str, str]] = []
        for tag in soup.find_all("script", src=True):
            tags.append(("script", str(tag["src"]).strip(), str(tag.get("integrity", "")).strip()))
        for tag in soup.find_all("link", rel=True, href=True):
            rels = [r.lower() for r in tag.get("rel", [])]
            if "stylesheet" in rels:
                tags.append(
                    ("stylesheet", str(tag["href"]).strip(), str(tag.get("integrity", "")).strip())
                )

        for kind, raw_ref, integrity_val in tags:
            if not raw_ref or raw_ref.startswith("data:"):
                continue
            resolved_ref = urljoin(page_url, raw_ref)
            parsed = urlparse(resolved_ref)
            ref_host = (parsed.hostname or "").lower()
            if not ref_host or ref_host == target_hostname.lower():
                continue

            has_sri = integrity_val.startswith(("sha256-", "sha384-", "sha512-"))

            external_resources.append(
                {
                    "type": kind,
                    "url": resolved_ref,
                    "host": ref_host,
                    "has_sri": has_sri,
                    "scheme": parsed.scheme,
                }
            )

            if kind == "script" and not has_sri and resolved_ref not in missing_sri_scripts:
                missing_sri_scripts.append(resolved_ref)

            if is_https_page and parsed.scheme == "http" and resolved_ref not in mixed_content_urls:
                mixed_content_urls.append(resolved_ref)

        if missing_sri_scripts:
            findings.append(
                FindingDraft(
                    title=f"Scripts externos cargados sin Subresource Integrity (SRI) ({len(missing_sri_scripts)})",
                    technical_description=(
                        "La página carga scripts desde dominios/CDNs de terceros sin atributo "
                        "'integrity'. Si el proveedor externo resulta comprometido, el navegador "
                        "ejecutará código alterado sin verificación criptográfica."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A08:2025",
                    secondary_owasp_codes=["A03:2025"],
                    affected_component=", ".join(missing_sri_scripts[:5]),
                    cwe_id="CWE-353",
                    evidence={"scripts_without_sri": missing_sri_scripts[:25]},
                    remediation_steps=(
                        "Añadir atributos integrity='sha384-...' y crossorigin='anonymous' a cada "
                        "etiqueta <script> y <link> externa, o servir los assets desde el propio origen."
                    ),
                    remediation_snippets={
                        "html": (
                            f'<script src="{missing_sri_scripts[0]}"\n'
                            '        integrity="sha384-<HASH_SHA384_GENERADO>"\n'
                            '        crossorigin="anonymous"></script>'
                        )
                    },
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        if mixed_content_urls:
            findings.append(
                FindingDraft(
                    title=f"Contenido mixto inseguro (HTTP) en página HTTPS ({len(mixed_content_urls)})",
                    technical_description=(
                        "La página HTTPS referencia scripts u hojas de estilo externos sobre HTTP sin cifrar."
                    ),
                    severity=SeverityLevel.HIGH,
                    owasp_category_code="A04:2025",
                    secondary_owasp_codes=["A08:2025"],
                    affected_component=", ".join(mixed_content_urls[:5]),
                    cwe_id="CWE-319",
                    evidence={"mixed_content_urls": mixed_content_urls},
                    remediation_steps="Migrar todas las referencias externas a https:// con SRI.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        return external_resources

    def _lookup_nvd_cves(
        self,
        ctx: ScanContext,
        technologies: list[dict[str, Any]],
        url: str,
        findings: list[FindingDraft],
    ) -> list[dict[str, Any]]:
        versioned = [t for t in technologies if t.get("version")]
        if not versioned:
            return []

        redis_client = self._get_redis_client()
        matches: list[dict[str, Any]] = []

        for tech in versioned[:5]:
            kw = tech["nvd_keyword"]
            ver = tech["version"]
            ctx.log(f"Consultando NVD API para {tech['name']} {ver}...")
            cves = self._fetch_nvd_cached(redis_client, kw, ver)
            if not cves:
                continue

            matches.append({"technology": tech["label"], "cves": cves})
            top_cve = max(cves, key=lambda c: c["cvss_score"] or 0.0)
            max_cvss = top_cve["cvss_score"] or 0.0
            top_vector = top_cve.get("cvss_vector")
            severity = self._cvss_to_severity(max_cvss)
            cve_ids = [c["id"] for c in cves]

            findings.append(
                FindingDraft(
                    title=f"Vulnerabilidades conocidas asociadas a {tech['label']} ({len(cve_ids)} CVE)",
                    technical_description=(
                        f"El cruce pasivo contra NVD API 2.0 identificó {len(cve_ids)} CVE(s) "
                        f"relacionados con {tech['label']}: {', '.join(cve_ids)}."
                    ),
                    severity=severity,
                    owasp_category_code="A03:2025",
                    affected_component=f"{tech['label']} ({url})",
                    cwe_id="CWE-1104",
                    cve_ids=cve_ids,
                    cvss_score=max_cvss or None,
                    cvss_vector=top_vector,
                    evidence={"technology": tech, "cves": cves},
                    remediation_steps=(
                        f"Actualizar {tech['name']} (versión detectada {ver}) a la última versión "
                        "estable parcheada y verificar aplicabilidad de los CVEs listados."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cid}" for cid in cve_ids[:5]],
                )
            )

        return matches

    def _get_redis_client(self) -> redis.Redis | None:
        try:
            return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
        except Exception:
            return None

    def _fetch_nvd_cached(
        self,
        redis_client: redis.Redis | None,
        keyword: str,
        version: str,
    ) -> list[dict[str, Any]]:
        cache_key = f"nvd:cve:{keyword}:{version}".lower().replace(" ", "_")
        if redis_client is not None:
            try:
                cached = redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        headers = {"User-Agent": "WebSecAuditDashboard/1.0"}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(
                    settings.NVD_API_BASE_URL,
                    params={
                        "keywordSearch": f"{keyword} {version}",
                        "resultsPerPage": 5,
                    },
                    headers=headers,
                )
            if resp.status_code != 200:
                return []
            payload = resp.json()
        except Exception:
            return []

        results: list[dict[str, Any]] = []
        for item in payload.get("vulnerabilities", [])[:5]:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")
            if not cve_id:
                continue
            descriptions = cve_obj.get("descriptions", [])
            desc_text = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )
            cvss_score, cvss_vector = self._extract_cvss_metrics(cve_obj.get("metrics", {}))
            results.append(
                {
                    "id": cve_id,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "summary": desc_text[:300],
                }
            )

        if redis_client is not None and results:
            try:
                redis_client.setex(cache_key, 43200, json.dumps(results))
            except Exception:
                pass

        return results

    @staticmethod
    def _extract_cvss_metrics(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key)
            if isinstance(metric_list, list) and metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                parsed_score = float(score) if isinstance(score, (int, float)) else None
                parsed_vector = str(vector).strip() if isinstance(vector, str) and vector.strip() else None
                if parsed_score is not None or parsed_vector is not None:
                    return parsed_score, parsed_vector
        return None, None

    @staticmethod
    def _cvss_to_severity(score: float) -> SeverityLevel:
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score > 0.0:
            return SeverityLevel.LOW
        return SeverityLevel.INFO
