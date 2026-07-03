"""
test_assessment_wizard — Unit-Tests für AssessmentRunner und Wizard-Hilfsfunktionen.

Testet ohne PySide6-GUI:
  - berechne_gewichtungen: Normalisierung auf aktive Bereiche
  - AssessmentRunner: Abbruch-Flag, Schritt-Iteration (gemockt)
  - ScoreComponent-Integration: Fehlschlag → Score 0
  - system_scanner-Integration: ohne Scan → Score 50, veralteter Scan → Warnung

Schichtzugehörigkeit: tests/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from tools.security_scoring.gui.dialogs.assessment_runner import (
    TESTBEREICHE,
    AssessmentRunner,
    berechne_gewichtungen,
)

# ---------------------------------------------------------------------------
# berechne_gewichtungen
# ---------------------------------------------------------------------------


class TestBerechneGewichtungen:
    def test_alle_bereiche_normalisiert_auf_1(self):
        gewichtungen = berechne_gewichtungen(TESTBEREICHE)
        gesamt = sum(gewichtungen.values())
        assert abs(gesamt - 1.0) < 1e-9

    def test_alle_bereiche_keys_vorhanden(self):
        gewichtungen = berechne_gewichtungen(TESTBEREICHE)
        for bereich in TESTBEREICHE:
            assert bereich["key"] in gewichtungen

    def test_proportionale_verteilung(self):
        bereiche = [
            {"key": "a", "gewichtung": 0.5},
            {"key": "b", "gewichtung": 0.5},
        ]
        gewichtungen = berechne_gewichtungen(bereiche)
        assert abs(gewichtungen["a"] - 0.5) < 1e-9
        assert abs(gewichtungen["b"] - 0.5) < 1e-9

    def test_ungleiche_verteilung(self):
        bereiche = [
            {"key": "x", "gewichtung": 0.25},
            {"key": "y", "gewichtung": 0.75},
        ]
        gewichtungen = berechne_gewichtungen(bereiche)
        assert abs(gewichtungen["x"] - 0.25) < 1e-9
        assert abs(gewichtungen["y"] - 0.75) < 1e-9

    def test_ein_bereich_ergibt_1_0(self):
        bereiche = [{"key": "only", "gewichtung": 0.20}]
        gewichtungen = berechne_gewichtungen(bereiche)
        assert abs(gewichtungen["only"] - 1.0) < 1e-9

    def test_leere_gewichtung_gleichverteilung(self):
        bereiche = [
            {"key": "a", "gewichtung": 0},
            {"key": "b", "gewichtung": 0},
        ]
        gewichtungen = berechne_gewichtungen(bereiche)
        assert abs(gewichtungen["a"] - 0.5) < 1e-9
        assert abs(gewichtungen["b"] - 0.5) < 1e-9

    def test_subset_bereiche(self):
        """Wenn nur 3 von 5 Bereichen aktiv sind, wird auf diese normalisiert."""
        subset = TESTBEREICHE[:3]
        gewichtungen = berechne_gewichtungen(subset)
        assert len(gewichtungen) == 3
        assert abs(sum(gewichtungen.values()) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# TESTBEREICHE-Konfiguration
# ---------------------------------------------------------------------------


class TestTestbereicheKonfiguration:
    def test_fuenf_bereiche_definiert(self):
        assert len(TESTBEREICHE) == 5

    def test_pflichtfelder_vorhanden(self):
        for bereich in TESTBEREICHE:
            assert "key" in bereich
            assert "name" in bereich
            assert "gewichtung" in bereich
            assert "icon" in bereich
            assert "standard_aktiv" in bereich

    def test_gewichtungen_summe_approx_1(self):
        gesamt = sum(b["gewichtung"] for b in TESTBEREICHE)
        assert abs(gesamt - 1.0) < 1e-9

    def test_standard_alle_aktiv(self):
        for bereich in TESTBEREICHE:
            assert bereich["standard_aktiv"] is True

    def test_eindeutige_keys(self):
        keys = [b["key"] for b in TESTBEREICHE]
        assert len(keys) == len(set(keys))

    def test_expected_keys(self):
        """password_policy entfernt, system_scanner hinzugefügt."""
        keys = {b["key"] for b in TESTBEREICHE}
        assert keys == {
            "api_security",
            "network_scanner",
            "cert_monitor",
            "dependency_auditor",
            "system_scanner",
        }

    def test_password_policy_nicht_mehr_vorhanden(self):
        """password_policy wurde aus TESTBEREICHE entfernt."""
        keys = [b["key"] for b in TESTBEREICHE]
        assert "password_policy" not in keys

    def test_system_scanner_vorhanden(self):
        """system_scanner ist in TESTBEREICHE enthalten."""
        keys = [b["key"] for b in TESTBEREICHE]
        assert "system_scanner" in keys


# ---------------------------------------------------------------------------
# AssessmentRunner — Abbruch-Flag
# ---------------------------------------------------------------------------


class TestAssessmentRunnerAbbrechen:
    def test_abbrechen_setzt_flag(self):
        runner = AssessmentRunner(
            services={},
            aktive_bereiche=[],
            klient_name="Test",
        )
        assert runner._abgebrochen is False  # noqa: SLF001
        runner.abbrechen()
        assert runner._abgebrochen is True  # noqa: SLF001

    def test_runner_initialisierung(self):
        services = {"api_security": MagicMock()}
        bereiche = TESTBEREICHE[:2]
        runner = AssessmentRunner(
            services=services,
            aktive_bereiche=bereiche,
            klient_name="ACME GmbH",
        )
        assert runner._klient == "ACME GmbH"  # noqa: SLF001
        assert len(runner._bereiche) == 2  # noqa: SLF001
        assert runner._score_repo is None  # noqa: SLF001

    def test_runner_mit_score_repo(self):
        repo = MagicMock()
        runner = AssessmentRunner(
            services={},
            aktive_bereiche=[],
            klient_name="K",
            score_repo=repo,
        )
        assert runner._score_repo is repo  # noqa: SLF001


# ---------------------------------------------------------------------------
# AssessmentRunner — _test_system_scanner (ohne echten Systemzugriff)
# ---------------------------------------------------------------------------


class TestAssessmentRunnerSystemScanner:
    """Tests für _test_system_scanner — alle mit gemocktem Repository."""

    def _make_runner(self) -> AssessmentRunner:
        return AssessmentRunner(
            services={},
            aktive_bereiche=[],
            klient_name="Test",
        )

    def test_kein_scan_liefert_score_50(self) -> None:
        """Kein vorhandener Scan → Score 50."""
        runner = self._make_runner()
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = None

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert score == 50.0
        assert crit == 0
        assert any("Kein System-Scan" in b for b in befunde)

    def test_veralteter_scan_liefert_score_50(self) -> None:
        """Scan älter als 30 Tage → Score 50, hohe Findings = 1."""
        from tools.system_scanner.domain.entities import OSInfo, ScanResult
        from tools.system_scanner.domain.enums import OSPlatform

        runner = self._make_runner()
        old_result = ScanResult(
            scan_id="old",
            timestamp=datetime.now(tz=UTC) - timedelta(days=35),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            security_components=[],
        )
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = old_result

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert score == 50.0
        assert high == 1
        assert any("Tage alt" in b for b in befunde)

    def test_aktueller_scan_alle_aktiv_liefert_score_100(self) -> None:
        """Frischer Scan, alle Komponenten aktiv → Score 100."""
        from tools.system_scanner.domain.entities import (
            OSInfo,
            ScanResult,
            SecurityComponent,
        )
        from tools.system_scanner.domain.enums import (
            ComponentStatus,
            ComponentType,
            OSPlatform,
        )

        runner = self._make_runner()
        result = ScanResult(
            scan_id="fresh",
            timestamp=datetime.now(tz=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            security_components=[
                SecurityComponent(
                    name="Defender",
                    type=ComponentType.ANTIVIRUS,
                    status=ComponentStatus.ACTIVE,
                ),
                SecurityComponent(
                    name="Firewall",
                    type=ComponentType.FIREWALL,
                    status=ComponentStatus.ACTIVE,
                ),
                SecurityComponent(
                    name="BitLocker",
                    type=ComponentType.ENCRYPTION,
                    status=ComponentStatus.ACTIVE,
                ),
            ],
        )
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = result

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert score == 100.0
        assert crit == 0
        assert high == 0

    def test_inaktiver_antivirus_senkt_score(self) -> None:
        """Inaktiver Antivirus → Score sinkt, high += 1."""
        from tools.system_scanner.domain.entities import (
            OSInfo,
            ScanResult,
            SecurityComponent,
        )
        from tools.system_scanner.domain.enums import (
            ComponentStatus,
            ComponentType,
            OSPlatform,
        )

        runner = self._make_runner()
        result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(tz=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            security_components=[
                SecurityComponent(
                    name="Defender",
                    type=ComponentType.ANTIVIRUS,
                    status=ComponentStatus.INACTIVE,
                )
            ],
        )
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = result

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert score < 100.0
        assert high >= 1
        assert any("inaktiv" in b.lower() for b in befunde)

    def test_inaktive_verschluesselung_erzeugt_kritisches_finding(self) -> None:
        """Inaktive Verschlüsselung → crit += 1."""
        from tools.system_scanner.domain.entities import (
            OSInfo,
            ScanResult,
            SecurityComponent,
        )
        from tools.system_scanner.domain.enums import (
            ComponentStatus,
            ComponentType,
            OSPlatform,
        )

        runner = self._make_runner()
        result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(tz=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            security_components=[
                SecurityComponent(
                    name="BitLocker",
                    type=ComponentType.ENCRYPTION,
                    status=ComponentStatus.INACTIVE,
                )
            ],
        )
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = result

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert crit >= 1
        assert score < 100.0

    def test_remote_access_tool_senkt_score(self) -> None:
        """Remote-Access-Tool mit RISK-Status → med += 1."""
        from tools.system_scanner.domain.entities import (
            OSInfo,
            ScanResult,
            SecurityComponent,
        )
        from tools.system_scanner.domain.enums import (
            ComponentStatus,
            ComponentType,
            OSPlatform,
        )

        runner = self._make_runner()
        result = ScanResult(
            scan_id="test",
            timestamp=datetime.now(tz=UTC),
            os_info=OSInfo(platform=OSPlatform.WINDOWS),
            security_components=[
                SecurityComponent(
                    name="TeamViewer",
                    type=ComponentType.REMOTE_ACCESS,
                    status=ComponentStatus.RISK,
                )
            ],
        )
        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = result

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            return_value=mock_repo,
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert med >= 1
        assert score < 100.0

    def test_repository_fehler_liefert_score_50(self) -> None:
        """DB-Fehler → Score 50, kein Absturz."""
        runner = self._make_runner()

        with patch(
            "tools.system_scanner.data.scanner_repository.ScanRepository",
            side_effect=RuntimeError("DB nicht erreichbar"),
        ):
            score, befunde, crit, high, med = runner._test_system_scanner()  # noqa: SLF001

        assert score == 50.0
        assert crit == 0


# ---------------------------------------------------------------------------
# AssessmentRunner — run Verhalten
# ---------------------------------------------------------------------------


class TestAssessmentRunnerRun:
    def test_run_leere_bereiche_keine_exception(self):
        """Leere Bereiche → run ohne Exception beendet sich."""
        runner = AssessmentRunner(
            services={},
            aktive_bereiche=[],
            klient_name="Leer",
        )
        runner.run()

    def test_run_mit_abbruch_keine_exception(self):
        """Abbruch vor dem ersten Bereich → run bricht sauber ab."""
        bereiche = TESTBEREICHE[:1]
        runner = AssessmentRunner(
            services={},
            aktive_bereiche=bereiche,
            klient_name="Abbruch",
        )
        runner.abbrechen()
        runner.run()
        assert runner._abgebrochen is True  # noqa: SLF001

    def test_run_mit_system_scanner_ergibt_score(self):
        """system_scanner-Bereich ohne vorhandenen Scan → Score 50 wird berechnet."""
        from tools.system_scanner.data.scanner_repository import ScanRepository

        bereiche = [b for b in TESTBEREICHE if b["key"] == "system_scanner"]
        runner = AssessmentRunner(
            services={},
            aktive_bereiche=bereiche,
            klient_name="SysScan-Test",
        )

        mock_repo = MagicMock()
        mock_repo.load_latest.return_value = None

        empfangene = []
        runner.alle_fertig.connect(empfangene.append)

        with patch.object(ScanRepository, "load_latest", return_value=None):
            runner.run()

        assert len(empfangene) == 1
        score = empfangene[0]
        assert score.target_name == "SysScan-Test"
        assert 0.0 <= score.overall_score <= 100.0
