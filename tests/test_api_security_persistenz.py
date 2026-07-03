"""
test_api_security_persistenz — Tests fuer ScanRepository und ScannerService-Persistenz.

Testet:
- ScanRepository: speichern + laden (Roundtrip)
- ScanRepository: Verlauf-Sortierung (neueste zuerst)
- ScanRepository: URL-Filter
- ScanRepository: Loeschen mit CASCADE
- ScanRepository: _sanitize_url entfernt Query-Parameter
- ScanRepository: JSON-Safety bei korruptem severity_summary_json
- ScannerService: run_scan persistiert im Repo
- ScannerService: Repo-Fehler bricht Scan nicht ab
- ScannerService: lade_verlauf ohne Repo gibt leere Liste
- ScannerService: vergleiche_scans — neu, behoben, bestehend

Alle Tests verwenden patch.object(edb, "DB_DIR", tmp_path) um die echte
produktive EncryptedDatabase-Ablage zu umgehen.

Author: Patrick Riederich
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import core.database.encrypted_db as edb
from tools.api_security.application.scanner_service import ScannerService
from tools.api_security.data.scan_repository import ScanRepository, _sanitize_url
from tools.api_security.domain.models import (
    APIType,
    AuthType,
    Finding,
    OWASPCategory,
    ScanLauf,
    ScanResult,
    ScanTarget,
    Severity,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_finding(
    code: str = "TEST_FINDING",
    title: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    """Erzeugt ein minimales Finding fuer Tests."""
    return Finding(
        code=code,
        title=title,
        description="Testbeschreibung",
        severity=severity,
        owasp=OWASPCategory.API8,
        detail="detail",
        remediation="fix it",
    )


def _make_lauf(
    target_url: str = "https://api.example.com/v1",
    findings: list[Finding] | None = None,
    scan_start: str = "2026-04-01T10:00:00+00:00",
    scan_end: str = "2026-04-01T10:00:05+00:00",
) -> ScanLauf:
    """Erzeugt einen minimalen ScanLauf fuer Tests."""
    f_list = findings if findings is not None else [_make_finding()]
    sev_summary = {}
    for f in f_list:
        sev_summary[f.severity.value] = sev_summary.get(f.severity.value, 0) + 1
    return ScanLauf(
        id=str(uuid.uuid4()),
        target_url=target_url,
        api_type="REST",
        scan_start=scan_start,
        scan_end=scan_end,
        total_checks=9,
        findings_count=len(f_list),
        severity_summary=sev_summary,
        findings=f_list,
    )


def _make_scan_result(
    url: str = "https://api.example.com/v1",
    findings: list[Finding] | None = None,
) -> ScanResult:
    """Erzeugt ein minimales ScanResult fuer Tests."""
    f_list = findings if findings is not None else [_make_finding()]
    target = ScanTarget(url=url, api_type=APIType.REST, auth_type=AuthType.NONE)
    now = datetime.now(UTC)
    return ScanResult(
        target=target,
        findings=f_list,
        scan_time=now.isoformat(),
        duration_ms=5000,
        error="",
    )


# ---------------------------------------------------------------------------
# ScanRepository — Speichern und Laden (Roundtrip)
# ---------------------------------------------------------------------------


class TestScanRepositoryRoundtrip:
    def test_speichern_und_laden_mit_findings(self, tmp_path):
        """Gespeicherter Lauf kann mit Findings vollstaendig geladen werden."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf = _make_lauf(
                findings=[
                    _make_finding("F1", "Finding1", Severity.CRITICAL),
                    _make_finding("F2", "Finding2", Severity.HIGH),
                ]
            )
            repo.speichere_lauf(lauf)

            result = repo.lade_lauf(lauf.id)

        assert result is not None
        assert result.id == lauf.id
        assert result.target_url == lauf.target_url
        assert result.findings_count == 2
        assert len(result.findings) == 2
        codes = {f.code for f in result.findings}
        assert codes == {"F1", "F2"}

    def test_laden_unbekannte_id_gibt_none(self, tmp_path):
        """lade_lauf mit unbekannter ID gibt None zurueck."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            result = repo.lade_lauf(str(uuid.uuid4()))
        assert result is None

    def test_insert_or_ignore_kein_duplikat(self, tmp_path):
        """Identischer Lauf zweimal gespeichert — kein Fehler, kein Duplikat."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf = _make_lauf()
            repo.speichere_lauf(lauf)
            repo.speichere_lauf(lauf)  # zweites Mal — INSERT OR IGNORE

            verlauf = repo.lade_verlauf()

        assert len(verlauf) == 1


# ---------------------------------------------------------------------------
# ScanRepository — Verlauf-Sortierung und URL-Filter
# ---------------------------------------------------------------------------


class TestScanRepositoryVerlauf:
    def test_verlauf_neueste_zuerst(self, tmp_path):
        """Verlauf gibt neueste Scans zuerst zurueck."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf_alt = _make_lauf(
                scan_start="2026-04-01T08:00:00+00:00",
                scan_end="2026-04-01T08:00:05+00:00",
            )
            lauf_neu = _make_lauf(
                scan_start="2026-04-01T12:00:00+00:00",
                scan_end="2026-04-01T12:00:05+00:00",
            )
            repo.speichere_lauf(lauf_alt)
            repo.speichere_lauf(lauf_neu)

            verlauf = repo.lade_verlauf()

        assert verlauf[0].id == lauf_neu.id
        assert verlauf[1].id == lauf_alt.id

    def test_verlauf_url_filter(self, tmp_path):
        """URL-Filter gibt nur Laeufe der angegebenen URL zurueck."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf_a = _make_lauf(target_url="https://api.example.com/v1")
            lauf_b = _make_lauf(target_url="https://other.example.com/api")
            repo.speichere_lauf(lauf_a)
            repo.speichere_lauf(lauf_b)

            result = repo.lade_verlauf(target_url="https://api.example.com/v1")

        assert len(result) == 1
        assert result[0].id == lauf_a.id

    def test_verlauf_ohne_findings(self, tmp_path):
        """Verlauf-Eintraege haben leere findings-Liste (nur Metadaten)."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf = _make_lauf(findings=[_make_finding()])
            repo.speichere_lauf(lauf)

            verlauf = repo.lade_verlauf()

        assert len(verlauf[0].findings) == 0

    def test_verlauf_limit(self, tmp_path):
        """Verlauf respektiert den Limit-Parameter."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            for i in range(5):
                lauf = _make_lauf(
                    scan_start=f"2026-04-0{i + 1}T10:00:00+00:00",
                    scan_end=f"2026-04-0{i + 1}T10:00:05+00:00",
                )
                repo.speichere_lauf(lauf)

            result = repo.lade_verlauf(limit=3)

        assert len(result) == 3

    def test_lade_alle_urls(self, tmp_path):
        """lade_alle_urls gibt distinct URLs alphabetisch sortiert zurueck."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            for url in [
                "https://z.example.com",
                "https://a.example.com",
                "https://z.example.com",
            ]:
                repo.speichere_lauf(_make_lauf(target_url=url))

            urls = repo.lade_alle_urls()

        assert urls == ["https://a.example.com", "https://z.example.com"]


# ---------------------------------------------------------------------------
# ScanRepository — Loeschen mit CASCADE
# ---------------------------------------------------------------------------


class TestScanRepositoryLoeschen:
    def test_loesche_lauf_entfernt_findings(self, tmp_path):
        """Nach Loeschen eines Laufs wird der Lauf und alle Findings entfernt."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf = _make_lauf(findings=[_make_finding("F1"), _make_finding("F2")])
            repo.speichere_lauf(lauf)
            repo.loesche_lauf(lauf.id)

            result = repo.lade_lauf(lauf.id)
            verlauf = repo.lade_verlauf()

        assert result is None
        assert len(verlauf) == 0

    def test_loesche_unbekannte_id_kein_fehler(self, tmp_path):
        """Loeschen einer nicht existierenden ID wirft keine Exception."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            repo.loesche_lauf(str(uuid.uuid4()))  # kein Fehler erwartet


# ---------------------------------------------------------------------------
# ScanRepository — URL-Bereinigung
# ---------------------------------------------------------------------------


class TestSanitizeUrl:
    def test_entfernt_query_parameter(self):
        url = "https://api.example.com/v1?api_key=secret&foo=bar"
        assert _sanitize_url(url) == "https://api.example.com/v1"

    def test_entfernt_fragment(self):
        url = "https://api.example.com/v1#section"
        assert _sanitize_url(url) == "https://api.example.com/v1"

    def test_unveraenderte_url_bleibt_gleich(self):
        url = "https://api.example.com/v1/endpoint"
        assert _sanitize_url(url) == url

    def test_url_mit_query_und_fragment(self):
        url = "https://api.example.com/v1?token=abc#top"
        assert _sanitize_url(url) == "https://api.example.com/v1"

    def test_sanitize_wird_vor_speicherung_angewendet(self, tmp_path):
        """In der DB gespeicherte URL hat keine Query-Parameter."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            dirty_url = "https://api.example.com/v1?api_key=supersecret"
            lauf = _make_lauf(target_url=dirty_url)
            repo.speichere_lauf(lauf)

            verlauf = repo.lade_verlauf()

        assert verlauf[0].target_url == "https://api.example.com/v1"
        assert "supersecret" not in verlauf[0].target_url


# ---------------------------------------------------------------------------
# ScanRepository — JSON-Safety bei korruptem severity_summary_json
# ---------------------------------------------------------------------------


class TestScanRepositoryJsonSafety:
    def test_korruptes_severity_summary_json_gibt_leeres_dict(self, tmp_path):
        """Korruptes JSON in severity_summary_json fuehrt zu severity_summary={}."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScanRepository()
            lauf = _make_lauf()
            repo.speichere_lauf(lauf)

            # Direkt in der DB den JSON-Wert korrumpieren
            with repo._db.connection() as conn:
                conn.execute(
                    "UPDATE api_scan_laeufe SET severity_summary_json = ? WHERE id = ?",
                    ("{INVALID_JSON_!!!", lauf.id),
                )

            result = repo.lade_lauf(lauf.id)

        assert result is not None
        assert result.severity_summary == {}


# ---------------------------------------------------------------------------
# ScannerService — Persistenz via run_scan
# ---------------------------------------------------------------------------


class TestScannerServicePersistenz:
    def _make_service_with_mock_repo(self):
        """Baut einen ScannerService mit Mock-Scanner und Mock-Repo."""
        mock_scanner = MagicMock()
        mock_reporter = MagicMock()
        mock_repo = MagicMock()

        scan_result = _make_scan_result()
        mock_scanner.scan.return_value = scan_result

        service = ScannerService(
            scanner=mock_scanner,
            reporter=mock_reporter,
            scan_repo=mock_repo,
        )
        return service, mock_repo, scan_result

    def test_run_scan_persistiert_im_repo(self):
        """run_scan ruft speichere_lauf auf dem Repo auf."""
        service, mock_repo, scan_result = self._make_service_with_mock_repo()
        target = ScanTarget(url="https://api.example.com/v1")

        service.run_scan(target)

        mock_repo.speichere_lauf.assert_called_once()
        # Uebergebener Lauf hat korrekte URL
        lauf_arg: ScanLauf = mock_repo.speichere_lauf.call_args[0][0]
        assert lauf_arg.target_url == "https://api.example.com/v1"
        assert lauf_arg.findings_count == len(scan_result.findings)

    def test_run_scan_repo_fehler_gibt_trotzdem_ergebnis(self):
        """Fehler beim Persistieren bricht den Scan nicht ab — Ergebnis wird zurueckgegeben."""
        service, mock_repo, scan_result = self._make_service_with_mock_repo()
        mock_repo.speichere_lauf.side_effect = RuntimeError("DB kaputt")
        target = ScanTarget(url="https://api.example.com/v1")

        result = service.run_scan(target)

        assert result is not None
        assert result.findings == scan_result.findings

    def test_run_scan_ohne_repo_kein_fehler(self):
        """run_scan ohne Repo-Konfiguration laeuft fehlerfrei durch."""
        mock_scanner = MagicMock()
        mock_reporter = MagicMock()
        scan_result = _make_scan_result()
        mock_scanner.scan.return_value = scan_result

        service = ScannerService(scanner=mock_scanner, reporter=mock_reporter)
        target = ScanTarget(url="https://api.example.com/v1")

        result = service.run_scan(target)

        assert result == scan_result

    def test_lade_verlauf_ohne_repo_gibt_leere_liste(self):
        """lade_verlauf gibt leere Liste wenn kein Repo konfiguriert."""
        mock_scanner = MagicMock()
        mock_reporter = MagicMock()
        service = ScannerService(scanner=mock_scanner, reporter=mock_reporter)

        result = service.lade_verlauf()

        assert result == []

    def test_lade_verlauf_delegiert_an_repo(self):
        """lade_verlauf delegiert Aufruf mit Parametern an das Repo."""
        service, mock_repo, _ = self._make_service_with_mock_repo()
        expected = [_make_lauf()]
        mock_repo.lade_verlauf.return_value = expected

        result = service.lade_verlauf(target_url="https://api.example.com", limit=5)

        mock_repo.lade_verlauf.assert_called_once_with("https://api.example.com", 5)
        assert result == expected

    def test_scan_mit_error_wird_nicht_persistiert(self):
        """run_scan persistiert nicht wenn ScanResult.error gesetzt ist."""
        mock_scanner = MagicMock()
        mock_reporter = MagicMock()
        mock_repo = MagicMock()

        error_result = ScanResult(
            target=ScanTarget(url="https://api.example.com/v1"),
            error="Verbindung fehlgeschlagen",
        )
        mock_scanner.scan.return_value = error_result

        service = ScannerService(
            scanner=mock_scanner, reporter=mock_reporter, scan_repo=mock_repo
        )
        target = ScanTarget(url="https://api.example.com/v1")
        service.run_scan(target)

        mock_repo.speichere_lauf.assert_not_called()


# ---------------------------------------------------------------------------
# ScannerService — vergleiche_scans
# ---------------------------------------------------------------------------


class TestVergleicheScans:
    def _make_lauf_mit_titles(self, titles: list[str]) -> ScanLauf:
        """Erzeugt einen ScanLauf mit Findings, die den angegebenen Titles entsprechen."""
        findings = [
            Finding(
                code=f"CODE_{t}",
                title=t,
                description="desc",
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.API8,
            )
            for t in titles
        ]
        return ScanLauf(
            id=str(uuid.uuid4()),
            target_url="https://api.example.com",
            api_type="REST",
            scan_start="2026-04-01T10:00:00+00:00",
            scan_end="2026-04-01T10:00:05+00:00",
            total_checks=9,
            findings_count=len(findings),
            severity_summary={"medium": len(findings)},
            findings=findings,
        )

    def _make_service(self) -> ScannerService:
        return ScannerService(scanner=MagicMock(), reporter=MagicMock())

    def test_diff_neu_behoben_bestehend(self):
        """Vergleich A(3) vs B(2, 1 gleich): 2 neu, 1 behoben, 1 bestehend."""
        service = self._make_service()
        # Vorheriger Scan: gemeinsam + behoben
        vorherig = self._make_lauf_mit_titles(["Gemeinsam", "Behoben"])
        # Aktueller Scan: gemeinsam + 2 neue
        aktuell = self._make_lauf_mit_titles(["Gemeinsam", "Neu1", "Neu2"])

        diff = service.vergleiche_scans(aktuell, vorherig)

        assert {f.title for f in diff["neu"]} == {"Neu1", "Neu2"}
        assert {f.title for f in diff["behoben"]} == {"Behoben"}
        assert {f.title for f in diff["bestehend"]} == {"Gemeinsam"}

    def test_identische_scans_alles_bestehend(self):
        """Identische Findings → alles bestehend, nichts neu oder behoben."""
        service = self._make_service()
        titles = ["F1", "F2", "F3"]
        lauf_a = self._make_lauf_mit_titles(titles)
        lauf_b = self._make_lauf_mit_titles(titles)

        diff = service.vergleiche_scans(lauf_a, lauf_b)

        assert len(diff["neu"]) == 0
        assert len(diff["behoben"]) == 0
        assert len(diff["bestehend"]) == 3

    def test_alle_neu_wenn_vorheriger_leer(self):
        """Vorheriger Scan ohne Findings → alle aktuellen Findings sind neu."""
        service = self._make_service()
        vorherig = self._make_lauf_mit_titles([])
        aktuell = self._make_lauf_mit_titles(["Neu1", "Neu2"])

        diff = service.vergleiche_scans(aktuell, vorherig)

        assert len(diff["neu"]) == 2
        assert len(diff["behoben"]) == 0
        assert len(diff["bestehend"]) == 0

    def test_alle_behoben_wenn_aktueller_leer(self):
        """Aktueller Scan ohne Findings → alle vorherigen Findings sind behoben."""
        service = self._make_service()
        vorherig = self._make_lauf_mit_titles(["Alt1", "Alt2"])
        aktuell = self._make_lauf_mit_titles([])

        diff = service.vergleiche_scans(aktuell, vorherig)

        assert len(diff["neu"]) == 0
        assert len(diff["behoben"]) == 2
        assert len(diff["bestehend"]) == 0
