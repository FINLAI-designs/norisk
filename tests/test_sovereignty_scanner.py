"""
test_sovereignty_scanner.

Tests fuer den DNS-MX + SPF + Software-Scan. Wir mocken
``dns.resolver.Resolver.resolve`` so dass kein echter Netzwerk-Call
geschieht. Software-Scan wird nur auf Windows ausgefuehrt und ist
hier durch Mock-Patches abgedeckt.
"""

from __future__ import annotations

from unittest.mock import patch

from tools.customer_audit.application.sovereignty_scanner import (
    SovereigntyScanner,
    build_rechtshinweise,
    is_valid_domain,
)
from tools.customer_audit.domain.entities import DetectedProvider


def test_is_valid_domain() -> None:
    assert is_valid_domain("kanzlei-mueller.at")
    assert is_valid_domain("example.co.uk")
    assert not is_valid_domain("nicht-domain")
    assert not is_valid_domain("")
    assert not is_valid_domain("https://kanzlei.at")


def test_scan_disabled_liefert_leer() -> None:
    scanner = SovereigntyScanner()
    report = scanner.scan(enabled=False, domain="kanzlei.at")
    assert report.detected == []
    assert report.errors == []


def test_scan_mx_microsoft(monkeypatch) -> None:
    """Simuliere MX-Antwort 'mx.kanzlei-mueller.mail.protection.outlook.com'."""

    class _FakeRdata:
        def __init__(self, host: str) -> None:
            self.exchange = host

    fake_mx = [_FakeRdata("kanzlei-mueller.mail.protection.outlook.com.")]

    def fake_resolve(self, target, rdtype, **_kw):  # noqa: ANN001
        if rdtype == "MX":
            return fake_mx
        # TXT-Antwort leer simulieren — keine SPF-Records
        raise RuntimeError("kein TXT")

    monkeypatch.setattr(
        "dns.resolver.Resolver.resolve", fake_resolve, raising=True
    )

    scanner = SovereigntyScanner()
    # Software-Scan ueberspringen
    with patch.object(scanner, "_scan_software"):
        report = scanner.scan(enabled=True, domain="kanzlei-mueller.at")

    assert len(report.detected) == 1
    p = report.detected[0]
    assert p.name == "Microsoft 365"
    assert p.via == "dns_mx"
    assert "protection.outlook.com" in p.evidence
    # TXT-Fehler ist in errors enthalten
    assert any("TXT" in e for e in report.errors)


def test_scan_mx_unbekannter_provider_wird_ignoriert(monkeypatch) -> None:
    """MX zeigt auf nicht-katalogisierten Provider → keine Detection."""

    class _FakeRdata:
        def __init__(self, host: str) -> None:
            self.exchange = host

    fake_mx = [_FakeRdata("mail.exotic-provider.example.")]

    def fake_resolve(self, target, rdtype, **_kw):  # noqa: ANN001
        return fake_mx

    monkeypatch.setattr(
        "dns.resolver.Resolver.resolve", fake_resolve, raising=True
    )

    scanner = SovereigntyScanner()
    with patch.object(scanner, "_scan_software"):
        report = scanner.scan(enabled=True, domain="exotic-kanzlei.at")
    assert report.detected == []


def test_scan_spf_extrahiert_includes(monkeypatch) -> None:
    """TXT-Record mit ``v=spf1 include:spf.protection.outlook.com -all``
    → Microsoft-Match."""

    class _FakeMX:
        exchange = "fallback.example."

    class _FakeTxt:
        strings = (b"v=spf1 include:spf.protection.outlook.com -all",)

    def fake_resolve(self, target, rdtype, **_kw):  # noqa: ANN001
        if rdtype == "MX":
            return [_FakeMX()]
        return [_FakeTxt()]

    monkeypatch.setattr(
        "dns.resolver.Resolver.resolve", fake_resolve, raising=True
    )
    scanner = SovereigntyScanner()
    with patch.object(scanner, "_scan_software"):
        report = scanner.scan(enabled=True, domain="kanzlei.at")
    namen = {p.name for p in report.detected}
    assert "Microsoft 365" in namen


def test_scan_domain_invalid(monkeypatch) -> None:
    """Ungueltige Domain → Fehler in Errors, kein DNS-Lookup."""
    scanner = SovereigntyScanner()
    with patch.object(scanner, "_scan_software"):
        report = scanner.scan(enabled=True, domain="nicht-domain")
    assert any("Domain" in e for e in report.errors)
    assert report.detected == []


def test_build_rechtshinweise_kanzlei_bekommt_brao_hinweis() -> None:
    detected = [
        DetectedProvider(
            name="Microsoft 365",
            status="cloud_act",
            category="office_suite",
            via="dns_mx",
            evidence="x.outlook.com",
        ),
    ]
    hints = build_rechtshinweise("Anwaltskanzlei", detected)
    assert hints
    assert any("§43e BRAO" in h or "BRAO" in h for h in hints)


def test_build_rechtshinweise_eu_boundary_text() -> None:
    detected = [
        DetectedProvider(
            name="Microsoft 365",
            status="eu_boundary",
            category="office_suite",
            via="dns_mx",
            evidence="x.outlook.com",
            residual_risk_note="Mutterkonzern bleibt CLOUD-Act-pflichtig.",
        ),
    ]
    hints = build_rechtshinweise("Sonstige", detected)
    assert any("Mutterkonzern" in h for h in hints)


def test_build_rechtshinweise_eu_sovereign_keine_warnung() -> None:
    detected = [
        DetectedProvider(
            name="Hetzner", status="eu_sovereign", category="saas_other",
            via="dns_mx", evidence="mx.hetzner.com",
        ),
    ]
    assert build_rechtshinweise("Anwaltskanzlei", detected) == []


def test_scan_tech_stack_matcht_provider(monkeypatch) -> None:
    """: ein im Tech-Stack erfasster Dienst taucht als via=tech_stack auf.

    Der Souveraenitaets-Scanner laed jetzt zusaetzlich den im security_scoring
    erfassten eigenen Tech-Stack (Cross-Tool lazy ueber core-Resolver) und
    gleicht ihn gegen den Provider-Catalog ab.
    """
    from tools.customer_audit.application import sovereignty_scanner as ss

    monkeypatch.setattr(ss, "external_fetches_allowed", lambda: True)
    monkeypatch.setattr(ss, "get_own_tech_stack_names", lambda: ["Dropbox"])
    scanner = ss.SovereigntyScanner()
    with patch.object(scanner, "_scan_software"):  # Registry-Scan ueberspringen
        report = scanner.scan(enabled=True, domain="")  # kein DNS -> kein Netz
    treffer = [p for p in report.detected if p.via == "tech_stack"]
    assert any("dropbox" in p.name.lower() for p in treffer)
