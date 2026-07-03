"""test_offline_mode — Offline-Modus-Gating.

Bei ``external_fetches_enabled=False`` (Offline-Modus) ueberspringen ALLE externen
Sicherheits-Abrufe den Netzwerkpfad — die automatischen (Cyber-Dashboard RSS-
Lagebild + CVE-Abruf, HIBP-Leak-Abgleich) UND die on-demand/button-ausgeloesten
Dritt-Daten-Lookups (VirusTotal, CSAF, OSV-Dependency-Audit, Threat-Feeds/
AbuseIPDB, NVD-Techstack-Suche, Consumer-Briefing-Feeds, Patch-Custom-Source).
Jeder gesperrte Pfad meldet den Hinweis im bestehenden Fehlerkanal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from core import feed_settings
from core.patch_custom_source import CustomSource, Platform
from core.security import virustotal_client as vt_mod
from tools.api_security.application import scanner_service as scan_mod
from tools.api_security.application.scanner_service import ScannerService
from tools.api_security.domain.models import ScanTarget
from tools.cert_monitor.application import cert_monitor_service as cms_mod
from tools.cert_monitor.application.cert_monitor_service import CertMonitorService
from tools.cert_monitor.domain.models import CertStatus
from tools.csaf_advisor.application import advisory_service as as_mod
from tools.csaf_advisor.application.advisory_service import AdvisoryService
from tools.customer_audit.application import sovereignty_scanner as sov_mod
from tools.customer_audit.application.sovereignty_scanner import SovereigntyScanner
from tools.cyber_dashboard.application import consumer_feeds_service as cfs_mod
from tools.cyber_dashboard.application import dashboard_service as ds_mod
from tools.cyber_dashboard.application.consumer_feeds_service import (
    ConsumerFeedsService,
)
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.dependency_auditor.data import pypi_advisory_client as pac_mod
from tools.dependency_auditor.data.pypi_advisory_client import PyPIAdvisoryClient
from tools.network_monitor.application import threat_feed_service as tfs_mod
from tools.network_monitor.application.threat_feed_service import ThreatFeedService
from tools.network_monitor.data import threat_feed_client as tfc_mod
from tools.network_monitor.data.threat_feed_client import ThreatFeedClient
from tools.password_checker.application import password_service as ps_mod
from tools.password_checker.application.password_service import PasswordService
from tools.patch_monitor.application import custom_source_checker as csc_mod
from tools.patch_monitor.application.custom_source_checker import CustomSourceChecker

# ---------------------------------------------------------------------------
# Cyber-Dashboard: RSS-Lagebild + CVE-Abruf
# ---------------------------------------------------------------------------


def test_lade_meldungen_offline_kein_netz(monkeypatch):
    monkeypatch.setattr(ds_mod, "external_fetches_allowed", lambda *a, **k: False)
    rss = MagicMock()
    cache = MagicMock()
    cache.ist_frisch.return_value = False  # normal -> Live-Load faellig
    cache.lade_meldungen.return_value = []
    svc = DashboardService(rss=rss, cache=cache)

    svc.lade_meldungen(erzwingen=True)

    rss.lade_meldungen.assert_not_called()  # KEIN Netz im Offline-Modus
    cache.lade_meldungen.assert_called()  # nur Cache


def test_lade_meldungen_online_laedt_live(monkeypatch):
    # Gegenprobe: Online-Modus -> der Live-Load laeuft.
    monkeypatch.setattr(ds_mod, "external_fetches_allowed", lambda *a, **k: True)
    rss = MagicMock()
    rss.lade_meldungen.return_value = []
    cache = MagicMock()
    cache.ist_frisch.return_value = False
    cache.lade_meldungen.return_value = []
    svc = DashboardService(rss=rss, cache=cache)

    svc.lade_meldungen(erzwingen=True)

    rss.lade_meldungen.assert_called_once()


def test_lade_cves_offline_frueh_zurueck(monkeypatch):
    monkeypatch.setattr(ds_mod, "external_fetches_allowed", lambda *a, **k: False)
    svc = DashboardService(rss=MagicMock(), cache=MagicMock())
    svc._lade_csaf_cves = MagicMock()  # type: ignore[method-assign]

    svc.lade_cves(erzwingen=True)

    svc._lade_csaf_cves.assert_not_called()  # Early-Return vor jedem Fetch


# ---------------------------------------------------------------------------
# Passwort-Checker: HIBP-Leak-Abgleich
# ---------------------------------------------------------------------------


def test_pruefen_offline_kein_hibp(monkeypatch):
    monkeypatch.setattr(ps_mod, "external_fetches_allowed", lambda *a, **k: False)
    hibp = MagicMock()
    svc = PasswordService(hibp_client=hibp)

    svc.pruefen("Sommer2026!#xQ", mit_breach_check=True)

    hibp.ist_kompromittiert.assert_not_called()  # kein SHA-1-Praefix an HIBP


def test_pruefen_online_nutzt_hibp(monkeypatch):
    monkeypatch.setattr(ps_mod, "external_fetches_allowed", lambda *a, **k: True)
    hibp = MagicMock()
    hibp.ist_kompromittiert.return_value = (False, 0)
    svc = PasswordService(hibp_client=hibp)

    svc.pruefen("Sommer2026!#xQ", mit_breach_check=True)

    hibp.ist_kompromittiert.assert_called_once()


# ---------------------------------------------------------------------------
# On-demand-Aktionen (Voll-Offline): button-/user-ausgeloeste Dritt-Daten-
# Lookups sind im Offline-Modus ebenfalls gesperrt — mit Hinweis im
# bestehenden Fehlerkanal statt stillem No-Op/Falsch-Entwarnung.
# ---------------------------------------------------------------------------


def test_virustotal_offline_kein_lookup(monkeypatch):
    monkeypatch.setattr(vt_mod, "external_fetches_allowed", lambda *a, **k: False)
    # gueltige Hash-Laenge -> Gate greift VOR API-Key/Netz.
    res = vt_mod.lookup_hash("a" * 64)

    assert res.status == "error"
    assert feed_settings.OFFLINE_HINT in res.message


def test_dependency_osv_offline_leer(monkeypatch):
    monkeypatch.setattr(pac_mod, "external_fetches_allowed", lambda *a, **k: False)
    client = PyPIAdvisoryClient()
    client._client = MagicMock()  # type: ignore[attr-defined]

    assert client.query_vulnerabilities("requests", "2.0.0") == []
    client._client.post.assert_not_called()  # kein OSV-Abruf


def test_csaf_fetch_offline_hinweis(monkeypatch):
    monkeypatch.setattr(as_mod, "external_fetches_allowed", lambda *a, **k: False)
    repo = MagicMock()
    svc = AdvisoryService(repository=repo)

    count, errors = svc.fetch_all_providers()

    assert count == 0
    assert errors == [feed_settings.OFFLINE_HINT]
    repo.list_providers.assert_not_called()  # gar nicht erst zur Provider-Liste


def test_threat_feed_offline_nicht_geladen(monkeypatch):
    monkeypatch.setattr(tfc_mod, "external_fetches_allowed", lambda *a, **k: False)
    client = ThreatFeedClient()
    client._client = MagicMock()  # type: ignore[attr-defined]

    res = client.fetch(MagicMock())

    assert res.ok is False
    assert feed_settings.OFFLINE_HINT in res.error
    client._client.get_capped.assert_not_called()


def test_abuseipdb_offline_kein_versand(monkeypatch):
    monkeypatch.setattr(tfs_mod, "external_fetches_allowed", lambda *a, **k: False)
    svc = ThreatFeedService(client=MagicMock(), cache=MagicMock())
    svc._load_abuseipdb_key = MagicMock()  # type: ignore[method-assign]

    verdaechtig, _grund = svc.abuseipdb_lookup("203.0.113.7", consent=True)

    assert verdaechtig is False
    svc._load_abuseipdb_key.assert_not_called()  # IP verlaesst das Geraet nicht


def test_consumer_feeds_offline_leer(monkeypatch):
    monkeypatch.setattr(cfs_mod, "external_fetches_allowed", lambda *a, **k: False)
    svc = ConsumerFeedsService()

    assert svc.lade_meldungen() == []  # kein RSS-Abruf fuers Briefing


def test_techstack_cve_offline_nur_lokal(monkeypatch):
    # NVD-Online-Zweig offline aus; lokale CPE-Treffer bleiben unberuehrt.
    monkeypatch.setattr(ds_mod, "external_fetches_allowed", lambda *a, **k: False)
    nvd = MagicMock()
    svc = DashboardService(rss=MagicMock(), cache=MagicMock(), nvd=nvd)
    eintrag = MagicMock()
    eintrag.aktiv = True
    eintrag.cpe = None
    monkeypatch.setattr(svc, "nvd_aktiv", lambda: True)
    monkeypatch.setattr(svc, "lade_techstack", lambda: [eintrag])

    svc.suche_cves_fuer_stack(tage=30)

    nvd.suche_produkt.assert_not_called()  # kein NVD-Netz offline


def test_custom_source_offline_nicht_geprueft(monkeypatch):
    monkeypatch.setattr(csc_mod, "external_fetches_allowed", lambda *a, **k: False)
    fetch = MagicMock()
    checker = CustomSourceChecker(fetch=fetch)
    src = CustomSource(
        id="x",
        name="Vendor",
        vendor_url="https://example.com",
        version_regex=r"(\d+\.\d+)",
        platform=Platform.WINDOWS,
        installed_version=None,
        available_version=None,
        last_checked_at=None,
        last_error=None,
        notes=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = checker.check(src)

    assert result.last_error == feed_settings.OFFLINE_HINT
    fetch.assert_not_called()  # kein Netz-Fetch der Vendor-Seite


# ---------------------------------------------------------------------------
# User-Ziel-Aktionen (Voll-Offline): aktive Scanner gegen ein vom User
# benanntes Ziel verlassen das Geraet ebenfalls nicht im Offline-Modus.
# (LAN-Scan im network_scanner bleibt erlaubt — kein Internet/Dritt-Daten.)
# ---------------------------------------------------------------------------


def test_api_scan_offline_kein_netz(monkeypatch):
    monkeypatch.setattr(scan_mod, "external_fetches_allowed", lambda *a, **k: False)
    scanner = MagicMock()
    svc = ScannerService(scanner=scanner, reporter=MagicMock())

    res = svc.scan(ScanTarget(url="https://api.example.com"))

    assert res.error == feed_settings.OFFLINE_HINT
    scanner.scan.assert_not_called()  # kein HTTP an das Ziel


def test_cert_scan_offline_fehler_hinweis(monkeypatch):
    monkeypatch.setattr(cms_mod, "external_fetches_allowed", lambda *a, **k: False)
    scanner = MagicMock()
    repo = MagicMock()
    svc = CertMonitorService(scanner=scanner, repo=repo)

    cert = svc.scanne_domain("example.com")

    assert cert.status == CertStatus.FEHLER
    assert cert.fehler_meldung == feed_settings.OFFLINE_HINT
    scanner.scan.assert_not_called()  # kein TLS-Handshake
    repo.speichere_ergebnis.assert_not_called()  # kein Fake-Ergebnis persistiert


def test_sovereignty_scan_offline_hinweis(monkeypatch):
    monkeypatch.setattr(sov_mod, "external_fetches_allowed", lambda *a, **k: False)
    scanner = SovereigntyScanner()

    report = scanner.scan(enabled=True, domain="example.com")

    assert report.errors == [feed_settings.OFFLINE_HINT]
    assert report.detected == []  # kein DNS-Lookup ausgehend
