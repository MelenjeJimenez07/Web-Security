"""Unit tests for Anti-SSRF, Anti-Command Injection, and Domain Ownership Verification."""

import socket
import types
from contextlib import contextmanager

import dns.resolver
import httpx
import pytest

from app.core.exceptions import SSRFBlockedError, TargetValidationError
from app.core.security import (
    check_domain_ownership_dns_txt,
    generate_verification_challenge,
    is_public_routable_ip,
    parse_and_normalize_target,
    resolve_and_validate_ips,
    run_safe_command,
    safe_http_get,
)
from app.models.enums import TargetType, VerificationMethod


class TestAntiSSRF:
    @pytest.mark.parametrize(
        "blocked_ip",
        [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ],
    )
    def test_private_and_reserved_ips_are_blocked(self, blocked_ip: str) -> None:
        assert is_public_routable_ip(blocked_ip) is False

    @pytest.mark.parametrize(
        "public_ip",
        ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"],
    )
    def test_public_routable_ips_are_allowed(self, public_ip: str) -> None:
        assert is_public_routable_ip(public_ip) is True

    @pytest.mark.parametrize(
        "bad_target",
        [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/resource",
            "http://localhost/admin",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://service.internal",
            "https://printer.local",
        ],
    )
    def test_ssrf_schemes_and_internal_hostnames_blocked(self, bad_target: str) -> None:
        with pytest.raises(SSRFBlockedError):
            parse_and_normalize_target(bad_target)

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "",
            "example.com;cat /etc/passwd",
            "example.com | whoami",
            "https://user:pass@example.com",
            "-oX /tmp/pwn",
            "singlelabel",
        ],
    )
    def test_malformed_or_injection_targets_rejected(self, malicious_input: str) -> None:
        with pytest.raises(TargetValidationError):
            parse_and_normalize_target(malicious_input)

    def test_target_normalization_formats(self) -> None:
        ttype, norm, host, scheme, port = parse_and_normalize_target("HTTPS://Example.COM:443/app")
        assert ttype == TargetType.URL
        assert norm == "https://example.com"
        assert host == "example.com"
        assert scheme == "https"
        assert port == 443

        ttype2, norm2, host2, _, _ = parse_and_normalize_target("https://[2606:4700:4700::1111]:8443")
        assert ttype2 == TargetType.URL
        assert norm2 == "https://[2606:4700:4700::1111]:8443"
        assert host2 == "2606:4700:4700::1111"

    def test_dns_resolution_blocks_mixed_private_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(SSRFBlockedError):
            resolve_and_validate_ips("rebind.example.com")

    def test_safe_http_get_blocks_redirect_to_metadata(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "app.core.security.resolve_and_validate_ips",
            lambda host: ("169.254.169.254",) if "169.254" in host else ("93.184.216.34",),
        )

        class FakeStreamResponse:
            status_code = 302
            is_redirect = True
            headers = httpx.Headers({"location": "http://169.254.169.254/latest/meta-data/"})
            url = httpx.URL("https://example.com")
            charset_encoding = "utf-8"

            def iter_bytes(self):
                yield b""

        @contextmanager
        def fake_stream(*_args: object, **_kwargs: object):
            yield FakeStreamResponse()

        monkeypatch.setattr(httpx.Client, "stream", fake_stream)
        with pytest.raises(SSRFBlockedError):
            safe_http_get("https://example.com")

    def test_lab_allowlist_permits_only_configured_dev_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core import security as sec_mod

        monkeypatch.setattr(sec_mod.settings, "APP_ENV", "development")
        monkeypatch.setattr(sec_mod.settings, "ALLOW_LAB_LOCAL_TARGETS", True)
        monkeypatch.setattr(
            sec_mod.settings,
            "LAB_TARGET_ALLOWLIST",
            ["localhost", "host.docker.internal"],
        )

        ttype, norm, host, _, port = parse_and_normalize_target("http://localhost:3001")
        assert ttype == TargetType.URL
        assert norm == "http://localhost:3001"
        assert host == "localhost"
        assert port == 3001

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
        )
        assert resolve_and_validate_ips("localhost") == ("127.0.0.1",)

        # Non-allowlisted internal names remain strictly blocked
        with pytest.raises(SSRFBlockedError):
            parse_and_normalize_target("http://192.168.1.50/admin")
        with pytest.raises(SSRFBlockedError):
            resolve_and_validate_ips("192.168.1.50")

    def test_lab_allowlist_always_blocks_metadata_and_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core import security as sec_mod

        monkeypatch.setattr(sec_mod.settings, "ALLOW_LAB_LOCAL_TARGETS", True)
        monkeypatch.setattr(
            sec_mod.settings,
            "LAB_TARGET_ALLOWLIST",
            ["localhost", "metadata.google.internal", "169.254.169.254"],
        )

        # Even in development, cloud metadata hostnames and IPs are unconditionally blocked
        monkeypatch.setattr(sec_mod.settings, "APP_ENV", "development")
        with pytest.raises(SSRFBlockedError):
            parse_and_normalize_target("http://metadata.google.internal/")
        with pytest.raises(SSRFBlockedError):
            resolve_and_validate_ips("169.254.169.254")

        # In production, allowlist is completely inactive
        monkeypatch.setattr(sec_mod.settings, "APP_ENV", "production")
        with pytest.raises(SSRFBlockedError):
            parse_and_normalize_target("http://localhost:3001")


class TestAntiCommandInjection:
    def test_run_safe_command_forces_shell_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run(argv: list[str], **kwargs: object) -> types.SimpleNamespace:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr("subprocess.run", fake_run)
        res = run_safe_command(["nmap", "-sT", "--", "93.184.216.34"], timeout_seconds=30)
        assert res.returncode == 0
        assert captured["argv"] == ["nmap", "-sT", "--", "93.184.216.34"]
        assert captured["kwargs"]["shell"] is False

    def test_run_safe_command_rejects_null_bytes(self) -> None:
        with pytest.raises(TargetValidationError):
            run_safe_command(["nmap", "93.184.216.34\x00--script=evil"])


class TestOwnershipVerification:
    def test_generate_verification_challenges(self) -> None:
        token_dns, loc_dns = generate_verification_challenge(
            "example.com", VerificationMethod.DNS_TXT
        )
        assert token_dns.startswith("websec-audit-verify=")
        assert loc_dns == "_websec-audit.example.com"

        token_web, loc_web = generate_verification_challenge(
            "example.com", VerificationMethod.WELL_KNOWN_FILE, scheme="https"
        )
        assert token_web.startswith("websec-audit-verify=")
        assert loc_web == "https://example.com/.well-known/security-audit.txt"

    def test_check_dns_txt_ownership_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakeRdata:
            strings = [b"websec-audit-verify=abcdef123456"]

        def fake_resolve(self, qname: str, rdtype: str):
            assert qname == "_websec-audit.example.com"
            assert rdtype == "TXT"
            return [FakeRdata()]

        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
        ok, err = check_domain_ownership_dns_txt("example.com", "websec-audit-verify=abcdef123456")
        assert ok is True
        assert err is None
