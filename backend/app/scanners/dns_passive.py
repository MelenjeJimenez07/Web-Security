"""Module 4: DNS Enumeration, SPF/DMARC Validation & Passive CT Logs (crt.sh)."""

import dns.exception
import dns.resolver
import httpx

from app.core.config import get_settings
from app.models.enums import SeverityLevel, TargetType
from app.scanners.base import BaseAuditScanner, FindingDraft, ModuleScanResult, ScanContext

settings = get_settings()

_SENSITIVE_SUBDOMAIN_KEYWORDS = (
    "admin",
    "staging",
    "stage",
    "dev",
    "test",
    "qa",
    "internal",
    "intranet",
    "vpn",
    "bastion",
    "jenkins",
    "gitlab",
    "db",
    "phpmyadmin",
)


class DnsPassiveScanner(BaseAuditScanner):
    """Queries DNS records, validates SPF/DMARC policies, and discovers subdomains via crt.sh."""

    module_key = "dns_passive"
    module_name = "Enumeración DNS y Superficie Pasiva"
    description = (
        "Consulta registros DNS (A, AAAA, MX, TXT, NS, CNAME, CAA), valida políticas SPF/DMARC "
        "y enumera subdominios pasivos mediante logs públicos de Certificate Transparency (crt.sh)."
    )
    is_active = False
    default_owasp_categories = ["A02:2025"]

    def run(self, ctx: ScanContext) -> ModuleScanResult:
        if ctx.target_type == TargetType.IP:
            return ModuleScanResult(
                module_key=self.module_key,
                module_name=self.module_name,
                skipped_reason="El objetivo es una dirección IP literal; se omite enumeración DNS de dominio.",
                raw_output={"skipped": True, "reason": "ip_target"},
                summary_metrics={"skipped": True},
            )

        domain = ctx.hostname.lower().rstrip(".")
        ctx.log(f"Consultando registros DNS y políticas SPF/DMARC para {domain}...")

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 8.0

        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA"):
            records[rtype] = self._query_records(resolver, domain, rtype)

        dmarc_records = self._query_records(resolver, f"_dmarc.{domain}", "TXT")
        dnssec_ds = self._query_records(resolver, domain, "DS")

        findings: list[FindingDraft] = []
        self._validate_spf(domain, records["TXT"], findings)
        self._validate_dmarc(domain, dmarc_records, findings)

        if not records["CAA"]:
            findings.append(
                FindingDraft(
                    title="Registro DNS CAA ausente",
                    technical_description=(
                        f"El dominio {domain} no publica registros CAA (Certification Authority "
                        "Authorization), permitiendo que cualquier CA emita certificados si no se restringe."
                    ),
                    severity=SeverityLevel.INFO,
                    owasp_category_code="A02:2025",
                    affected_component=domain,
                    cwe_id="CWE-16",
                    evidence={"caa_records": []},
                    remediation_steps=(
                        "Publicar un registro DNS CAA autorizando únicamente a las CAs empleadas "
                        "(ej. 0 issue \"letsencrypt.org\")."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        ctx.log(f"Consultando Certificate Transparency logs (crt.sh) para %.{domain}...")
        subdomains, crt_error = self._query_crt_sh(domain)
        self._evaluate_subdomains(domain, subdomains, findings)

        ctx.log(
            f"Enumeración DNS completada: {len(subdomains)} subdominio(s) único(s) en crt.sh.",
            level="info",
            data={"subdomains_count": len(subdomains), "crt_sh_error": crt_error},
        )

        return ModuleScanResult(
            module_key=self.module_key,
            module_name=self.module_name,
            findings=findings,
            raw_output={
                "domain": domain,
                "records": records,
                "dmarc_records": dmarc_records,
                "dnssec_signed": bool(dnssec_ds),
                "subdomains": subdomains[:200],
                "total_subdomains_discovered": len(subdomains),
                "crt_sh_error": crt_error,
            },
            summary_metrics={
                "subdomains_count": len(subdomains),
                "dnssec_signed": bool(dnssec_ds),
                "spf_present": any(r.lower().startswith("v=spf1") for r in records["TXT"]),
                "dmarc_present": any(r.lower().startswith("v=dmarc1") for r in dmarc_records),
            },
        )

    def _query_records(self, resolver: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(name, rtype)
            results: list[str] = []
            for rdata in answers:
                if rtype == "TXT":
                    val = "".join(
                        p.decode("utf-8", errors="ignore") if isinstance(p, bytes) else str(p)
                        for p in rdata.strings
                    )
                    results.append(val)
                else:
                    results.append(rdata.to_text())
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException:
            return []

    def _validate_spf(
        self, domain: str, txt_records: list[str], findings: list[FindingDraft]
    ) -> None:
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
        if not spf_records:
            findings.append(
                FindingDraft(
                    title="Registro SPF (Sender Policy Framework) ausente",
                    technical_description=(
                        f"El dominio {domain} carece de registro TXT SPF (v=spf1), facilitando la "
                        "suplantación de identidad de correo (email spoofing)."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A02:2025",
                    affected_component=domain,
                    cwe_id="CWE-290",
                    evidence={"txt_records": txt_records},
                    remediation_steps=(
                        "Publicar un registro TXT SPF especificando los servidores autorizados y "
                        "finalizando con '-all' (ej. 'v=spf1 include:_spf.tuproveedor.com -all')."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
            return

        if len(spf_records) > 1:
            findings.append(
                FindingDraft(
                    title="Múltiples registros SPF detectados (violación RFC 7208)",
                    technical_description=(
                        f"Se encontraron {len(spf_records)} registros v=spf1 en {domain}; RFC 7208 "
                        "solo permite uno y los receptores devolverán error PermError."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A02:2025",
                    affected_component=domain,
                    cwe_id="CWE-16",
                    evidence={"spf_records": spf_records},
                    remediation_steps="Consolidar todos los mecanismos autorizados en un único registro TXT v=spf1.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

        for spf in spf_records:
            lowered = spf.lower()
            if "+all" in lowered:
                findings.append(
                    FindingDraft(
                        title="Política SPF excesivamente permisiva (+all)",
                        technical_description=(
                            f"El registro SPF '{spf}' incluye '+all', autorizando a cualquier servidor "
                            "de Internet a enviar correos en nombre del dominio."
                        ),
                        severity=SeverityLevel.HIGH,
                        owasp_category_code="A02:2025",
                        affected_component=domain,
                        cwe_id="CWE-290",
                        evidence={"spf": spf},
                        remediation_steps="Reemplazar '+all' por '-all' (hardfail) o '~all' durante transición.",
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )
            elif "?all" in lowered:
                findings.append(
                    FindingDraft(
                        title="Política SPF neutral (?all) sin protección efectiva",
                        technical_description=f"El registro SPF '{spf}' usa mecanismo neutral '?all'.",
                        severity=SeverityLevel.LOW,
                        owasp_category_code="A02:2025",
                        affected_component=domain,
                        cwe_id="CWE-290",
                        evidence={"spf": spf},
                        remediation_steps="Cambiar '?all' por '-all' una vez validados todos los emisores legítimos.",
                        references=["https://owasp.org/Top10/2025/"],
                    )
                )

    def _validate_dmarc(
        self, domain: str, dmarc_records: list[str], findings: list[FindingDraft]
    ) -> None:
        valid_dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
        if not valid_dmarc:
            findings.append(
                FindingDraft(
                    title="Registro DMARC ausente (_dmarc)",
                    technical_description=(
                        f"No existe registro TXT DMARC en _dmarc.{domain}, impidiendo instruir a "
                        "los servidores receptores sobre cómo rechazar o aislar correos suplantados."
                    ),
                    severity=SeverityLevel.MEDIUM,
                    owasp_category_code="A02:2025",
                    affected_component=f"_dmarc.{domain}",
                    cwe_id="CWE-290",
                    evidence={"dmarc_records": dmarc_records},
                    remediation_steps=(
                        f"Crear un registro TXT en _dmarc.{domain} con política de cumplimiento, ej.: "
                        "'v=DMARC1; p=quarantine; rua=mailto:dmarc@dominio.com; adkim=s; aspf=s'."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
            return

        policy = valid_dmarc[0]
        if "p=none" in policy.lower():
            findings.append(
                FindingDraft(
                    title="Política DMARC en modo solo monitoreo (p=none)",
                    technical_description=(
                        f"El registro DMARC '{policy}' tiene p=none, por lo que no bloquea ni envía "
                        "a cuarentena correos que fallen autenticación SPF/DKIM."
                    ),
                    severity=SeverityLevel.LOW,
                    owasp_category_code="A02:2025",
                    affected_component=f"_dmarc.{domain}",
                    cwe_id="CWE-290",
                    evidence={"dmarc": policy},
                    remediation_steps="Migrar gradualmente de p=none a p=quarantine y posteriormente p=reject.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )

    def _query_crt_sh(self, domain: str) -> tuple[list[str], str | None]:
        url = f"{settings.CRT_SH_BASE_URL.rstrip('/')}/"
        try:
            with httpx.Client(timeout=12.0, follow_redirects=True) as client:
                resp = client.get(
                    url,
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"User-Agent": "WebSecAuditDashboard/1.0"},
                )
            if resp.status_code != 200:
                return [], f"crt.sh respondió HTTP {resp.status_code}"
            entries = resp.json()
            if not isinstance(entries, list):
                return [], "Respuesta inesperada desde crt.sh"
        except Exception as exc:
            return [], str(exc)

        discovered: set[str] = set()
        for row in entries:
            if not isinstance(row, dict):
                continue
            raw_names = str(row.get("name_value") or "")
            for line in raw_names.splitlines():
                candidate = line.strip().lower().lstrip("*.")
                if candidate == domain or candidate.endswith(f".{domain}"):
                    discovered.add(candidate)

        return sorted(discovered), None

    def _evaluate_subdomains(
        self, domain: str, subdomains: list[str], findings: list[FindingDraft]
    ) -> None:
        if not subdomains:
            return

        sensitive = [
            sub
            for sub in subdomains
            if any(
                kw in sub.removesuffix(f".{domain}").split(".")
                for kw in _SENSITIVE_SUBDOMAIN_KEYWORDS
            )
        ]

        if sensitive:
            findings.append(
                FindingDraft(
                    title=f"Subdominios administrativos o pre-producción visibles en Certificate Transparency ({len(sensitive)})",
                    technical_description=(
                        "Los registros públicos de Certificate Transparency (crt.sh) revelan "
                        f"subdominios potencialmente sensibles ({', '.join(sensitive[:10])})."
                    ),
                    severity=SeverityLevel.LOW,
                    owasp_category_code="A02:2025",
                    secondary_owasp_codes=["A01:2025"],
                    affected_component=domain,
                    cwe_id="CWE-200",
                    evidence={"sensitive_subdomains": sensitive[:30]},
                    remediation_steps=(
                        "Verificar que entornos dev/staging/admin no sean accesibles públicamente "
                        "sin VPN/autenticación y usar certificados internos cuando corresponda."
                    ),
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
        else:
            findings.append(
                FindingDraft(
                    title=f"Superficie pasiva descubierta: {len(subdomains)} subdominio(s) en CT logs",
                    technical_description=(
                        f"Se enumeraron pasivamente {len(subdomains)} subdominios asociados a {domain} "
                        "mediante Certificate Transparency logs."
                    ),
                    severity=SeverityLevel.INFO,
                    owasp_category_code="A02:2025",
                    affected_component=domain,
                    cwe_id="CWE-200",
                    evidence={"subdomains_sample": subdomains[:25], "total": len(subdomains)},
                    remediation_steps="Mantener inventario actualizado de subdominios y retirar registros DNS huérfanos.",
                    references=["https://owasp.org/Top10/2025/"],
                )
            )
