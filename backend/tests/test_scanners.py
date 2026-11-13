"""Unit tests for all 5 modular OWASP Top 10:2025 audit scanner plugins."""

import datetime as dt
import types

import dns.resolver
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.security import SafeHttpResponse
from app.models.enums import ScanProfile, SeverityLevel, TargetType
from app.scanners.dns_passive import DnsPassiveScanner
from app.scanners.http_headers import HttpHeadersScanner
from app.scanners.nmap_recon import NmapReconScanner
from app.scanners.registry import get_all_module_keys, validate_module_keys
from app.scanners.ssl_tls import SslTlsScanner
from app.scanners.tech_supply_chain import TechSupplyChainScanner
from tests.conftest import make_scan_context

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -Pn -T4 --top-ports 100 --open -oX - -- 93.184.216.34">
  <host starttime="1700000000" endtime="1700000005">
    <status state="up" reason="syn-ack"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack"/>
        <service name="redis" product="Redis key-value store" version="7.0.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _build_test_certificate_der(*, days_offset_end: int = -5) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(now + dt.timedelta(days=days_offset_end))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_registry_contains_all_five_modules() -> None:
    keys = get_all_module_keys()
    assert set(keys) == {
        "dns_passive",
        "nmap_recon",
        "ssl_tls",
        "http_headers",
        "tech_supply_chain",
    }
    assert validate_module_keys(["nmap_recon", "nmap_recon"]) == ["nmap_recon"]


def test_nmap_recon_scanner_detects_exposed_ports_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_cmd: list[str] = []

    def fake_run_cmd(argv: list[str], **_kwargs: object) -> types.SimpleNamespace:
        captured_cmd.extend(argv)
        return types.SimpleNamespace(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

    monkeypatch.setattr("app.scanners.nmap_recon.run_safe_command", fake_run_cmd)
    monkeypatch.setattr(
        "app.scanners.nmap_recon.safe_http_get",
        lambda url, **_kw: (
            SafeHttpResponse(
                status_code=404 if "/admin" not in url else 200,
                url=url,
                headers=httpx.Headers({}),
                set_cookies=(),
                content=b"",
                text="",
            ),
            [url],
        ),
    )

    ctx = make_scan_context(scan_profile=ScanProfile.SERVICE_VERSION)
    result = NmapReconScanner().run(ctx)

    assert captured_cmd[0] == "nmap"
    assert "-sV" in captured_cmd
    assert "--" in captured_cmd
    assert captured_cmd[-1] == "93.184.216.34"
    assert result.summary_metrics["open_ports_count"] == 3
    titles = [f.title for f in result.findings]
    assert any("6379/tcp" in t for t in titles)
    assert any("/admin" in t for t in titles)
    assert all(f.owasp_category_code in {"A01:2025", "A02:2025"} for f in result.findings)


def test_http_headers_scanner_grades_and_tags_owasp(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_http_get(url: str, **_kwargs: object):
        if "nonexistent-404" in url:
            body = "Werkzeug powered traceback: File '/app/views.py', line 12"
            return (
                SafeHttpResponse(
                    status_code=500,
                    url=url,
                    headers=httpx.Headers({}),
                    set_cookies=(),
                    content=body.encode(),
                    text=body,
                ),
                [url],
            )
        headers = httpx.Headers(
            [
                ("server", "nginx/1.18.0"),
                ("set-cookie", "sessionid=abc123; Path=/"),
            ]
        )
        return (
            SafeHttpResponse(
                status_code=200,
                url=url,
                headers=headers,
                set_cookies=("sessionid=abc123; Path=/",),
                content=b"<html><body>Home</body></html>",
                text="<html><body>Home</body></html>",
            ),
            [url],
        )

    monkeypatch.setattr("app.scanners.http_headers.safe_http_get", fake_http_get)
    ctx = make_scan_context()
    result = HttpHeadersScanner().run(ctx)

    owasp_codes = {f.owasp_category_code for f in result.findings}
    assert {"A02:2025", "A05:2025", "A07:2025", "A10:2025"}.issubset(owasp_codes)
    assert result.raw_output["grade"] in {"D", "F"}
    csp_finding = next(f for f in result.findings if "Content-Security-Policy" in f.title)
    assert "nginx" in csp_finding.remediation_snippets
    assert "apache" in csp_finding.remediation_snippets


def test_ssl_tls_scanner_flags_expired_untrusted_and_deprecated_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired_der = _build_test_certificate_der(days_offset_end=-10)
    scanner = SslTlsScanner()

    monkeypatch.setattr(
        scanner,
        "_check_trust_chain",
        lambda *_args: (False, "self-signed certificate"),
    )
    monkeypatch.setattr(
        scanner,
        "_fetch_cert_and_cipher",
        lambda *_args: (
            expired_der,
            "TLSv1.2",
            {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "protocol": "TLSv1.2", "bits": 112},
        ),
    )
    monkeypatch.setattr(
        scanner,
        "_probe_tls_protocols",
        lambda *_args: ["TLSv1.0", "TLSv1.2"],
    )

    ctx = make_scan_context()
    result = scanner.run(ctx)

    assert all(f.owasp_category_code == "A04:2025" for f in result.findings)
    severities = {f.severity for f in result.findings}
    assert SeverityLevel.CRITICAL in severities  # Expired cert
    assert SeverityLevel.HIGH in severities  # Untrusted, TLS 1.0, 3DES weak cipher


def test_dns_passive_scanner_validates_spf_dmarc_and_crtsh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRdata:
        def __init__(self, text: str) -> None:
            self._text = text
            self.strings = [text.encode()]

        def to_text(self) -> str:
            return self._text

    def fake_resolve(self, name: str, rtype: str):
        if rtype == "TXT" and name == "example.com":
            return [FakeRdata("v=spf1 +all")]
        if rtype == "TXT" and name == "_dmarc.example.com":
            raise dns.resolver.NXDOMAIN()
        if rtype == "A":
            return [FakeRdata("93.184.216.34")]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)

    class FakeHttpResponse:
        status_code = 200

        @staticmethod
        def json():
            return [
                {"name_value": "staging.example.com\nwww.example.com"},
                {"name_value": "*.example.com"},
            ]

    monkeypatch.setattr(httpx.Client, "get", lambda *_a, **_kw: FakeHttpResponse())

    ctx = make_scan_context(target_type=TargetType.DOMAIN, normalized_target="example.com")
    result = DnsPassiveScanner().run(ctx)

    assert all(f.owasp_category_code == "A02:2025" for f in result.findings)
    titles = [f.title for f in result.findings]
    assert any("SPF" in t and "+all" in t for t in titles)
    assert any("DMARC" in t for t in titles)
    assert "staging.example.com" in result.raw_output["subdomains"]

    # IP targets should skip cleanly
    ip_ctx = make_scan_context(
        target_type=TargetType.IP,
        normalized_target="93.184.216.34",
        hostname="93.184.216.34",
    )
    ip_result = DnsPassiveScanner().run(ip_ctx)
    assert ip_result.skipped_reason is not None


def test_tech_supply_chain_scanner_detects_missing_sri_and_cves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    html_doc = """
    <html>
      <head>
        <script src="https://cdn.thirdparty.net/jquery-3.4.1.min.js"></script>
      </head>
      <body>Test</body>
    </html>
    """
    monkeypatch.setattr(
        "app.scanners.tech_supply_chain.safe_http_get",
        lambda url, **_kw: (
            SafeHttpResponse(
                status_code=200,
                url=url,
                headers=httpx.Headers({"server": "nginx/1.18.0"}),
                set_cookies=(),
                content=html_doc.encode(),
                text=html_doc,
            ),
            [url],
        ),
    )

    scanner = TechSupplyChainScanner()
    monkeypatch.setattr(scanner, "_get_redis_client", lambda: None)

    class FakeNvdResp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2020-11022",
                            "descriptions": [{"lang": "en", "value": "XSS in jQuery"}],
                            "metrics": {
                                "cvssMetricV31": [{"cvssData": {"baseScore": 6.1}}]
                            },
                        }
                    }
                ]
            }

    monkeypatch.setattr(httpx.Client, "get", lambda *_a, **_kw: FakeNvdResp())

    ctx = make_scan_context()
    result = scanner.run(ctx)

    owasp_codes = {f.owasp_category_code for f in result.findings}
    assert "A08:2025" in owasp_codes  # Missing SRI
    assert "A03:2025" in owasp_codes  # Vulnerable supply chain component + inventory
    cve_findings = [f for f in result.findings if f.cve_ids]
    assert len(cve_findings) >= 1
    assert "CVE-2020-11022" in cve_findings[0].cve_ids
