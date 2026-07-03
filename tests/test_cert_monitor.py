"""tests/test_cert_monitor.py — Unit-Tests für den SSL/TLS-Zertifikats-Monitor.

Prüft:
  - Domain-Modelle (CertInfo, CertStatus)
  - CertAnalyzer (analysiere_zertifikat, berechne_tage_verbleibend)
  - CertRepository (CRUD in temporärer DB)
  - CertMonitorService (Domain-Verwaltung, Scan-Orchestrierung mit gemocktem Scanner)

Kein echtes Netzwerk-I/O — CertScanner wird vollständig gemockt.

Author: Patrick Riederich
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from tools.cert_monitor.domain.cert_analyzer import (
    analysiere_zertifikat,
    berechne_tage_verbleibend,
)
from tools.cert_monitor.domain.models import CertInfo, CertStatus

# ---------------------------------------------------------------------------
# berechne_tage_verbleibend
# ---------------------------------------------------------------------------


class TestBerechnetageVerbleibend:
    def test_leerer_string(self):
        assert berechne_tage_verbleibend("") == 0

    def test_abgelaufenes_zertifikat(self):
        gestern = (datetime.now(tz=UTC) - timedelta(days=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        assert berechne_tage_verbleibend(gestern) < 0

    def test_zertifikat_in_zukunft(self):
        morgen = (datetime.now(tz=UTC) + timedelta(days=100)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        tage = berechne_tage_verbleibend(morgen)
        assert 98 <= tage <= 101

    def test_nmap_format(self):
        # Format wie ssl.getpeercert zurückgibt
        zukunft = datetime.now(tz=UTC) + timedelta(days=50)
        fmt_str = zukunft.strftime("%b %d %H:%M:%S %Y GMT")
        tage = berechne_tage_verbleibend(fmt_str)
        assert 48 <= tage <= 52

    def test_ungueltig_gibt_null(self):
        assert berechne_tage_verbleibend("kein-datum") == 0


# ---------------------------------------------------------------------------
# analysiere_zertifikat
# ---------------------------------------------------------------------------


class TestAnalysiere:
    def _cert(self, **kwargs) -> CertInfo:
        defaults = {
            "domain": "test.at",
            "tls_version": "TLSv1.3",
            "cipher_bits": 256,
            "ist_self_signed": False,
        }
        defaults.update(kwargs)
        return CertInfo(**defaults)

    def test_ok_zertifikat(self):
        cert = self._cert(tage_verbleibend=100, gueltig_bis="2030-01-01")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.OK
        assert len(result.findings) == 0

    def test_kritisch_bei_30_tage(self):
        cert = self._cert(tage_verbleibend=29, gueltig_bis="2025-05-01")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.KRITISCH
        assert any("Tag" in f for f in result.findings)

    def test_warnung_bei_89_tage(self):
        cert = self._cert(tage_verbleibend=89, gueltig_bis="2025-07-01")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.WARNUNG
        assert any("Tage" in f for f in result.findings)

    def test_abgelaufenes_zertifikat(self):
        cert = self._cert(tage_verbleibend=0, gueltig_bis="2020-01-01")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.KRITISCH
        assert any("abgelaufen" in f.lower() for f in result.findings)

    def test_self_signed(self):
        cert = self._cert(tage_verbleibend=100, ist_self_signed=True)
        result = analysiere_zertifikat(cert)
        assert result.status in (CertStatus.WARNUNG, CertStatus.KRITISCH)
        assert any("elbst" in f for f in result.findings)  # Selbst-signiert

    def test_veraltete_tls_version(self):
        cert = self._cert(tage_verbleibend=100, tls_version="TLSv1.1")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.KRITISCH
        assert any("TLS" in f for f in result.findings)

    def test_tls_12_warnung(self):
        cert = self._cert(tage_verbleibend=100, tls_version="TLSv1.2")
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.WARNUNG
        assert any("1.2" in f for f in result.findings)

    def test_schwache_cipher(self):
        cert = self._cert(tage_verbleibend=100, cipher_bits=56)
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.KRITISCH
        assert any("Cipher" in f or "Bit" in f for f in result.findings)

    def test_fehler_status_unveraendert(self):
        cert = CertInfo(
            domain="fail.at", status=CertStatus.FEHLER, fehler_meldung="timeout"
        )
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.FEHLER

    def test_mehrere_probleme(self):
        cert = self._cert(
            tage_verbleibend=10, tls_version="TLSv1.1", ist_self_signed=True
        )
        result = analysiere_zertifikat(cert)
        assert result.status == CertStatus.KRITISCH
        assert len(result.findings) >= 2


# ---------------------------------------------------------------------------
# CertInfo Modell
# ---------------------------------------------------------------------------


class TestCertInfoModel:
    def test_anzeige_domain_standard_port(self):
        cert = CertInfo(domain="example.at", port=443)
        assert cert.anzeige_domain == "example.at"

    def test_anzeige_domain_nicht_standard_port(self):
        cert = CertInfo(domain="example.at", port=8443)
        assert cert.anzeige_domain == "example.at:8443"

    def test_default_status(self):
        cert = CertInfo(domain="example.at")
        assert cert.status == CertStatus.UNBEKANNT

    def test_default_findings_leer(self):
        cert = CertInfo(domain="example.at")
        assert cert.findings == []


# ---------------------------------------------------------------------------
# CertRepository
# ---------------------------------------------------------------------------


class TestCertRepository:
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        """Fixture mit temporärer DB-Pfad."""
        db_dir = tmp_path / ".finlai" / "db"
        db_dir.mkdir(parents=True)
        # DB_DIR ist eine Modul-Konstante — muss direkt gepatcht werden
        import core.database.encrypted_db as _edb

        monkeypatch.setattr(_edb, "DB_DIR", db_dir)

        from tools.cert_monitor.data.cert_repository import CertRepository

        return CertRepository()

    def test_domain_hinzufuegen_und_laden(self, repo):
        repo.fuge_domain_hinzu("example.at", 443)
        domains = repo.lade_domains()
        assert ("example.at", 443) in domains

    def test_domain_doppelt_ignoriert(self, repo):
        repo.fuge_domain_hinzu("example.at", 443)
        repo.fuge_domain_hinzu("example.at", 443)
        domains = repo.lade_domains()
        count = sum(1 for d, p in domains if d == "example.at")
        assert count == 1

    def test_domain_entfernen(self, repo):
        repo.fuge_domain_hinzu("example.at", 443)
        repo.entferne_domain("example.at", 443)
        domains = repo.lade_domains()
        assert ("example.at", 443) not in domains

    def test_ergebnis_speichern_und_laden(self, repo):
        cert = CertInfo(
            domain="example.at",
            port=443,
            aussteller="Let's Encrypt",
            gueltig_bis="2026-01-01",
            tage_verbleibend=200,
            tls_version="TLSv1.3",
            cipher_bits=256,
            status=CertStatus.OK,
            findings=[],
            letzte_pruefung="2025-01-01T00:00:00+00:00",
        )
        repo.speichere_ergebnis(cert)
        ergebnisse = repo.lade_ergebnisse()
        assert len(ergebnisse) == 1
        assert ergebnisse[0].domain == "example.at"
        assert ergebnisse[0].aussteller == "Let's Encrypt"
        assert ergebnisse[0].status == CertStatus.OK

    def test_ergebnis_aktualisieren(self, repo):
        cert1 = CertInfo(domain="example.at", port=443, status=CertStatus.UNBEKANNT)
        repo.speichere_ergebnis(cert1)
        cert2 = CertInfo(
            domain="example.at", port=443, status=CertStatus.OK, tage_verbleibend=100
        )
        repo.speichere_ergebnis(cert2)
        ergebnisse = repo.lade_ergebnisse()
        assert len(ergebnisse) == 1
        assert ergebnisse[0].status == CertStatus.OK


# ---------------------------------------------------------------------------
# CertMonitorService
# ---------------------------------------------------------------------------


class TestCertMonitorService:
    @pytest.fixture
    def service_mit_mock_repo(self):
        from tools.cert_monitor.application.cert_monitor_service import (
            CertMonitorService,
        )

        scanner = MagicMock()
        repo = MagicMock()
        repo.lade_domains.return_value = [("example.at", 443), ("test.at", 443)]
        scanner.scan.return_value = CertInfo(
            domain="example.at", port=443, status=CertStatus.OK
        )
        return CertMonitorService(scanner=scanner, repo=repo), scanner, repo

    def test_domain_hinzufuegen_normalisiert(self, service_mit_mock_repo):
        service, _, repo = service_mit_mock_repo
        service.domain_hinzufuegen("https://Example.AT/pfad", 443)
        repo.fuge_domain_hinzu.assert_called_once_with("example.at", 443)

    def test_domain_entfernen(self, service_mit_mock_repo):
        service, _, repo = service_mit_mock_repo
        service.domain_entfernen("example.at", 443)
        repo.entferne_domain.assert_called_once_with("example.at", 443)

    def test_scanne_domain_speichert_ergebnis(self, service_mit_mock_repo):
        service, scanner, repo = service_mit_mock_repo
        result = service.scanne_domain("example.at", 443)
        scanner.scan.assert_called_once_with("example.at", 443)
        repo.speichere_ergebnis.assert_called_once()
        assert result.domain == "example.at"

    def test_scanne_alle_ruft_alle_domains(self, service_mit_mock_repo):
        service, scanner, repo = service_mit_mock_repo
        service.scanne_alle()
        assert scanner.scan.call_count == 2

    def test_scanne_alle_robust_bei_scan_fehler(self, service_mit_mock_repo):
        """: ein crashendes Ziel bricht den Batch nicht ab — FEHLER-CertInfo."""
        service, scanner, repo = service_mit_mock_repo
        scanner.scan.side_effect = [
            RuntimeError("boom"),
            CertInfo(domain="test.at", port=443, status=CertStatus.OK),
        ]
        ergebnisse = service.scanne_alle()
        assert len(ergebnisse) == 2
        assert ergebnisse[0].status == CertStatus.FEHLER
        assert "boom" in ergebnisse[0].fehler_meldung
        assert ergebnisse[1].status == CertStatus.OK

    def test_fortschritt_callback_wird_aufgerufen(self, service_mit_mock_repo):
        service, _, _ = service_mit_mock_repo
        aufrufe = []
        service.scanne_alle(progress_callback=lambda c, t, d: aufrufe.append(c))
        assert len(aufrufe) == 3  # 0, 1, 2 (fertig)


# ---------------------------------------------------------------------------
# CertScanner — echter Parse-/Scan-Pfad: frozen CertInfo, kein Mutate)
# ---------------------------------------------------------------------------


class TestCertScannerRealPath:
    """Deckt den echten _parse_cert-/scan-Pfad ab (vorher ungetestet →)."""

    def test_parse_cert_immutable_und_befuellt(self):
        """_parse_cert füllt Felder via replace, ohne die frozen Instanz zu mutieren."""
        from tools.cert_monitor.data.cert_scanner import CertScanner

        base = CertInfo(domain="example.com", port=443)
        raw = {
            "issuer": [[("organizationName", "SSL Corp")]],
            "subject": [[("commonName", "example.com")]],
            "notAfter": "Aug 29 21:41:26 2026 GMT",
            "notBefore": "May  1 00:00:00 2026 GMT",
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
            "serialNumber": "ABC123",
        }
        result = CertScanner()._parse_cert(
            base, raw, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3"
        )
        assert result.aussteller == "SSL Corp"
        assert result.gueltig_bis == "Aug 29 21:41:26 2026 GMT"
        assert result.tls_version == "TLSv1.3"
        assert result.cipher_bits == 256
        assert "www.example.com" in result.san_domains
        assert result.serial_number == "ABC123"
        # Frozen-Basis bleibt unverändert (kein In-Place-Mutate → kein Crash)
        assert base.aussteller != "SSL Corp"

    def test_scan_verbindungsfehler_gibt_fehler_ohne_crash(self):
        """OSError beim Connect → FEHLER-Status, kein FrozenInstanceError."""
        from tools.cert_monitor.data.cert_scanner import CertScanner

        with patch(
            "socket.create_connection", side_effect=OSError("connection refused")
        ):
            result = CertScanner().scan("nicht-erreichbar.invalid", 443)
        assert result.status == CertStatus.FEHLER
        assert "connection refused" in result.fehler_meldung

    def test_scan_unverified_setzt_self_signed_via_replace(self):
        """_scan_unverified (Verify-Fehler-Pfad) setzt ist_self_signed via replace, kein Crash."""
        from tools.cert_monitor.data.cert_scanner import CertScanner

        fake_ssock = MagicMock()
        fake_ssock.__enter__.return_value = fake_ssock
        fake_ssock.__exit__.return_value = False
        fake_ssock.getpeercert.return_value = {
            "issuer": [[("commonName", "self")]],
            "subject": [[("commonName", "self")]],
            "notAfter": "Aug 29 21:41:26 2026 GMT",
            "serialNumber": "DEAD",
        }
        fake_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        fake_ssock.version.return_value = "TLSv1.3"
        fake_ctx = MagicMock()
        fake_ctx.wrap_socket.return_value = fake_ssock
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.__exit__.return_value = False

        base = CertInfo(domain="self.example", port=443)
        with (
            patch("socket.create_connection", return_value=fake_sock),
            patch("ssl._create_unverified_context", return_value=fake_ctx),
        ):
            result = CertScanner()._scan_unverified("self.example", 443, base)
        assert result.ist_self_signed is True
        assert result.serial_number == "DEAD"
