"""
test_security_scoring — Unit-Tests für das Security-Scoring-Dashboard.

Testet:
  - Scoring-Engine (calculate_component_score, calculate_overall_score, score_to_grade)
  - ScoringService-Aggregation (API Security, Netzwerk, Dependency-Mocks)
  - ScoreRepository-Persistenz (tmp_path, EncryptedDatabase)

Schichtzugehörigkeit: tests/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

import core.database.encrypted_db as edb
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.data.report_generator import (
    SecurityReportGenerator,
    _build_priorities,
    _finding_description,
)
from tools.security_scoring.data.score_repository import ScoreRepository
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore
from tools.security_scoring.domain.scoring_engine import (
    DEFAULT_WEIGHTS,
    calculate_component_score,
    calculate_overall_score,
    score_to_grade,
)

# ---------------------------------------------------------------------------
# Scoring-Engine
# ---------------------------------------------------------------------------


class TestCalculateComponentScore:
    def test_perfekt_keine_findings(self):
        assert calculate_component_score(0, 0, 0) == 100.0

    def test_ein_kritisches_finding(self):
        assert calculate_component_score(1, 0, 0) == 75.0

    def test_ein_hohes_finding(self):
        assert calculate_component_score(0, 1, 0) == 85.0

    def test_ein_mittleres_finding(self):
        assert calculate_component_score(0, 0, 1) == 95.0

    def test_niedrige_findings(self):
        assert calculate_component_score(0, 0, 0, 5) == 95.0

    def test_kombination(self):
        # 100 - 1*25 - 2*15 - 3*5 = 100 - 25 - 30 - 15 = 30
        assert calculate_component_score(1, 2, 3) == 30.0

    def test_minimum_null(self):
        assert calculate_component_score(10, 0, 0) == 0.0

    def test_viele_findings_null(self):
        assert calculate_component_score(5, 10, 20) == 0.0


class TestCalculateOverallScore:
    def test_leer_ergibt_null(self):
        assert calculate_overall_score([]) == 0.0

    def test_eine_komponente(self):
        c = ScoreComponent("A", 80.0, 1.0)
        assert calculate_overall_score([c]) == 80.0

    def test_gewichteter_durchschnitt(self):
        c1 = ScoreComponent("A", 100.0, 0.6)
        c2 = ScoreComponent("B", 50.0, 0.4)
        # (100*0.6 + 50*0.4) / 1.0 = 80
        assert calculate_overall_score([c1, c2]) == pytest.approx(80.0)

    def test_ungleiche_gewichtung(self):
        c1 = ScoreComponent("A", 100.0, 0.3)
        c2 = ScoreComponent("B", 0.0, 0.7)
        # (100*0.3 + 0*0.7) / 1.0 = 30
        assert calculate_overall_score([c1, c2]) == pytest.approx(30.0)

    def test_weight_null_ergibt_null(self):
        c = ScoreComponent("A", 100.0, 0.0)
        assert calculate_overall_score([c]) == 0.0


class TestCoverageCap:
    """ (c): Score wird durch Coverage gecappt — fehlen Daten in
    wesentlichen Bereichen, kann der Gesamtscore nicht falsch hoch sein.
    """

    def test_volle_coverage_score_unveraendert(self) -> None:
        """Alle Komponenten data_available=True → Coverage=100% → kein Cap."""
        c1 = ScoreComponent("A", 100.0, 0.5, data_available=True)
        c2 = ScoreComponent("B", 80.0, 0.5, data_available=True)
        # weighted_avg = 90, coverage = 1.0 → cap = 100 → min(90, 100) = 90
        assert calculate_overall_score([c1, c2]) == pytest.approx(90.0)

    def test_haelfte_coverage_score_gecappt(self) -> None:
        """Eine Komponente fehlt → Coverage=50% → Score gecappt auf 50.0."""
        c1 = ScoreComponent("A", 100.0, 0.5, data_available=True)
        c2 = ScoreComponent("B", 0.0, 0.5, data_available=False)
        # weighted_avg (nur c1) = 100, coverage = 0.5 → cap = 50.0
        assert calculate_overall_score([c1, c2]) == pytest.approx(50.0)

    def test_patrick_szenario_2_von_6_fehlen(self) -> None:
        """Patrick-Szenario: 4 von 6 Komponenten haben Daten, alle high.

        Vor (c): 96/100 trotz fehlender TechStack-Daten.
        Nach (c): Score gecappt auf 4/6 = 66.67.
        """
        comps = [
            ScoreComponent("API", 96.0, 0.25, data_available=True),
            ScoreComponent("Network", 96.0, 0.20, data_available=True),
            ScoreComponent("Cert", 96.0, 0.15, data_available=True),
            ScoreComponent("Password", 96.0, 0.10, data_available=True),
            ScoreComponent("CVE", 0.0, 0.15, data_available=False),
            ScoreComponent("Dep", 0.0, 0.15, data_available=False),
        ]
        result = calculate_overall_score(comps)
        # Active Weight = 0.25+0.20+0.15+0.10 = 0.70
        # Coverage = 0.70 / 1.00 = 0.70 → Cap = 70.0
        # weighted_avg = 96.0 (alle aktiven 96)
        # min(96, 70) = 70
        assert result == pytest.approx(70.0)

    def test_keine_aktiven_komponenten_ergibt_null(self) -> None:
        """Alle data_available=False → 0.0 (Coverage = 0%, kein Cap nötig)."""
        c1 = ScoreComponent("A", 100.0, 0.5, data_available=False)
        c2 = ScoreComponent("B", 100.0, 0.5, data_available=False)
        assert calculate_overall_score([c1, c2]) == 0.0


class TestCalculateCoverage:
    """ (c): Coverage-Helper als eigene Funktion."""

    def test_leer_ergibt_null(self) -> None:
        from tools.security_scoring.domain.scoring_engine import calculate_coverage
        assert calculate_coverage([]) == 0.0

    def test_alle_aktiv_ergibt_eins(self) -> None:
        from tools.security_scoring.domain.scoring_engine import calculate_coverage
        c1 = ScoreComponent("A", 80.0, 0.5, data_available=True)
        c2 = ScoreComponent("B", 60.0, 0.5, data_available=True)
        assert calculate_coverage([c1, c2]) == pytest.approx(1.0)

    def test_haelfte_aktiv_ergibt_haelfte(self) -> None:
        from tools.security_scoring.domain.scoring_engine import calculate_coverage
        c1 = ScoreComponent("A", 80.0, 0.5, data_available=True)
        c2 = ScoreComponent("B", 60.0, 0.5, data_available=False)
        assert calculate_coverage([c1, c2]) == pytest.approx(0.5)

    def test_gewichtete_coverage(self) -> None:
        """Coverage gewichtet mit Component-Weight, nicht Anzahl."""
        from tools.security_scoring.domain.scoring_engine import calculate_coverage
        c1 = ScoreComponent("Heavy", 80.0, 0.7, data_available=True)
        c2 = ScoreComponent("Light", 60.0, 0.3, data_available=False)
        # Active = 0.7, total = 1.0 → coverage = 0.7
        assert calculate_coverage([c1, c2]) == pytest.approx(0.7)


class TestScoreToGrade:
    def test_a_grade(self):
        assert score_to_grade(90.0) == "A"
        assert score_to_grade(100.0) == "A"

    def test_b_grade(self):
        assert score_to_grade(75.0) == "B"
        assert score_to_grade(89.9) == "B"

    def test_c_grade(self):
        assert score_to_grade(60.0) == "C"
        assert score_to_grade(74.9) == "C"

    def test_d_grade(self):
        assert score_to_grade(40.0) == "D"
        assert score_to_grade(59.9) == "D"

    def test_f_grade(self):
        assert score_to_grade(0.0) == "F"
        assert score_to_grade(39.9) == "F"


class TestDefaultWeights:
    def test_alle_keys_vorhanden(self):
        expected = {
            "api_security",
            "network_scanner",
            "dependency_auditor",
            "cert_monitor",
            "password_policy",
            "cve_exposure",
        }
        assert set(DEFAULT_WEIGHTS.keys()) == expected

    def test_summe_ist_eins(self):
        total = sum(DEFAULT_WEIGHTS.values())
        assert total == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# ScoringService-Aggregation (mit Mocks)
# ---------------------------------------------------------------------------


def _make_scan_lauf(crit: int = 0, high: int = 0, med: int = 0) -> MagicMock:
    """Erzeugt einen Mock-ScanLauf mit severity_summary."""
    lauf = MagicMock()
    lauf.severity_summary = {
        "critical": crit,
        "high": high,
        "medium": med,
        "low": 0,
    }
    lauf.scan_start = "2026-04-02T10:00:00+00:00"
    return lauf


def _make_network_scan(crit_ports: int = 0, high_ports: int = 1) -> MagicMock:
    """Erzeugt einen Mock-NetworkScanResult."""
    from tools.network_scanner.domain.models import PortRisk

    def _port(risk: PortRisk) -> MagicMock:
        p = MagicMock()
        p.risk = risk
        return p

    host = MagicMock()
    host.offene_ports = [_port(PortRisk.KRITISCH)] * crit_ports + [
        _port(PortRisk.HOCH)
    ] * high_ports

    scan = MagicMock()
    scan.hosts = [host]
    scan.gestartet_am = "2026-04-02T09:00:00+00:00"
    return scan


class TestScoringServiceOhneTools:
    def test_berechne_score_ohne_services(self):
        """Ohne externe Services: leere Komponenten → Score 0."""
        service = ScoringService()
        score = service.berechne_score("Test GmbH")
        assert score.overall_score == 0.0
        assert score.grade == "F"
        assert score.components == []

    def test_target_name_wird_uebernommen(self):
        service = ScoringService()
        score = service.berechne_score("Mustermann AG")
        assert score.target_name == "Mustermann AG"

    def test_id_ist_uuid(self):
        service = ScoringService()
        score = service.berechne_score("X")
        assert uuid.UUID(score.id)  # Kein ValueError → gültiger UUID

    def test_timestamp_ist_iso(self):
        service = ScoringService()
        score = service.berechne_score("X")
        dt = datetime.fromisoformat(score.timestamp)
        assert dt.tzinfo is not None


class TestScoringServiceMitApiSecurity:
    def test_api_security_keine_findings(self):
        api_mock = MagicMock()
        api_mock.lade_verlauf.return_value = [_make_scan_lauf(0, 0, 0)]

        service = ScoringService(api_security_service=api_mock)
        score = service.berechne_score("X")

        assert len(score.components) == 1
        comp = score.components[0]
        assert comp.source_tool == "api_security"
        assert comp.score == pytest.approx(100.0)

    def test_api_security_kritische_findings(self):
        api_mock = MagicMock()
        api_mock.lade_verlauf.return_value = [_make_scan_lauf(crit=2, high=1)]

        service = ScoringService(api_security_service=api_mock)
        score = service.berechne_score("X")

        comp = score.components[0]
        # 100 - 2*25 - 1*15 = 35
        assert comp.score == pytest.approx(35.0)
        assert comp.findings_critical == 2
        assert comp.findings_high == 1

    def test_api_security_kein_verlauf(self):
        api_mock = MagicMock()
        api_mock.lade_verlauf.return_value = []

        service = ScoringService(api_security_service=api_mock)
        score = service.berechne_score("X")
        assert score.components == []

    def test_api_security_exception_ignoriert(self):
        api_mock = MagicMock()
        api_mock.lade_verlauf.side_effect = RuntimeError("Verbindungsfehler")

        service = ScoringService(api_security_service=api_mock)
        score = service.berechne_score("X")
        assert score.components == []


class TestScoringServiceMitNetwork:
    def test_netzwerk_keine_risiken(self):

        host = MagicMock()
        host.offene_ports = []  # keine offenen Ports
        scan = MagicMock()
        scan.hosts = [host]
        scan.gestartet_am = "2026-04-02T09:00:00+00:00"

        net_mock = MagicMock()
        net_mock.lade_letzte_scans.return_value = [scan]

        service = ScoringService(network_service=net_mock)
        score = service.berechne_score("X")

        assert len(score.components) == 1
        assert score.components[0].score == pytest.approx(100.0)

    def test_netzwerk_kritische_ports(self):
        net_mock = MagicMock()
        net_mock.lade_letzte_scans.return_value = [
            _make_network_scan(crit_ports=2, high_ports=0)
        ]

        service = ScoringService(network_service=net_mock)
        score = service.berechne_score("X")

        comp = score.components[0]
        assert comp.source_tool == "network_scanner"
        # 100 - 2*25 = 50
        assert comp.score == pytest.approx(50.0)

    def test_netzwerk_kein_scan(self):
        net_mock = MagicMock()
        net_mock.lade_letzte_scans.return_value = []

        service = ScoringService(network_service=net_mock)
        score = service.berechne_score("X")
        assert score.components == []


class TestScoringServiceMitDependency:
    def _make_audit_result(self, crit=0, high=0, med=0, low=0):
        result = MagicMock()
        result.critical_count.return_value = crit
        result.high_count.return_value = high
        result.medium_count.return_value = med
        result.low_count.return_value = low
        result.scan_timestamp = "2026-04-02T08:00:00+00:00"
        return result

    def test_dependency_saubere_deps(self):
        service = ScoringService()
        audit = self._make_audit_result(0, 0, 0, 0)
        score = service.berechne_score("X", audit_result=audit)

        assert len(score.components) == 1
        assert score.components[0].source_tool == "dependency_auditor"
        assert score.components[0].score == pytest.approx(100.0)

    def test_dependency_kritische_vuln(self):
        service = ScoringService()
        audit = self._make_audit_result(crit=1, high=2)
        score = service.berechne_score("X", audit_result=audit)

        comp = score.components[0]
        # 100 - 1*25 - 2*15 = 45
        assert comp.score == pytest.approx(45.0)

    def test_dependency_ohne_audit_result(self):
        service = ScoringService()
        score = service.berechne_score("X", audit_result=None)
        assert score.components == []


class TestScoringServiceGesamtscore:
    def test_gewichteter_score_zwei_komponenten(self):
        api_mock = MagicMock()
        api_mock.lade_verlauf.return_value = [_make_scan_lauf(0, 0, 0)]  # Score 100

        net_mock = MagicMock()
        net_mock.lade_letzte_scans.return_value = [
            _make_network_scan(crit_ports=0, high_ports=0)
        ]

        service = ScoringService(
            api_security_service=api_mock,
            network_service=net_mock,
        )
        score = service.berechne_score("X")

        # Beide Komponenten Score 100
        assert score.overall_score == pytest.approx(100.0)
        assert score.grade == "A"

    def test_zusammenfassung_bei_findings(self):
        # Cleanup-Sprint 2026-04-29: scoring_service nutzt seit dem
        # CVSS-Anpassungs-Refactor die englische CVSS-Bezeichnung
        # "Critical" statt der deutschen "kritische" — passend zum
        # CVSS-3.1-Vokabular. Wir prüfen den semantisch stabilen Anker.
        api_mock = MagicMock()
        api_mock.lade_verlauf.return_value = [_make_scan_lauf(crit=1, high=0, med=0)]

        service = ScoringService(api_security_service=api_mock)
        score = service.berechne_score("X")

        assert "critical" in score.summary.lower()
        assert "1 finding" in score.summary.lower()


# ---------------------------------------------------------------------------
# ScoreRepository (Persistenz)
# ---------------------------------------------------------------------------


def _make_security_score(target: str = "Test AG", score: float = 72.0) -> SecurityScore:
    """Erzeugt einen Test-SecurityScore."""
    return SecurityScore(
        id=str(uuid.uuid4()),
        target_name=target,
        timestamp=datetime.now(UTC).isoformat(),
        overall_score=score,
        grade=score_to_grade(score),
        components=[
            ScoreComponent(
                name="API Security",
                score=score,
                weight=DEFAULT_WEIGHTS["api_security"],
                findings_critical=0,
                findings_high=1,
                last_scan="2026-04-02T10:00:00+00:00",
                source_tool="api_security",
            )
        ],
        summary=f"Score {score:.0f}/100.",
    )


_HSR_PATH = (
    "tools.security_scoring.data.hardening_score_repository."
    "HardeningScoreRepository"
)


class TestHardeningPersistenzT296:
    """: Hardening-Score wird nur bei ``target_name`` persistiert,
    der Verlauf-Lader reicht Tupel durch, und der Trend-Lookup liest die
    Tupel-Shape korrekt (Bugfix previous_hardening_score)."""

    def test_persistiert_bei_target_name(self):
        saved: list[tuple] = []

        class _FakeRepo:
            def save_score(self, target, result, *, subject_id=""):  # noqa: ANN001, ANN202
                saved.append((target, result))

        with patch(_HSR_PATH, _FakeRepo):
            service = ScoringService()
            result = service.compute_hardening_score(target_name="Mein System")

        assert len(saved) == 1
        assert saved[0][0] == "Mein System"
        assert saved[0][1] is result

    def test_keine_persistenz_ohne_target_name(self):
        saved: list[tuple] = []

        class _FakeRepo:
            def save_score(self, target, result, *, subject_id=""):  # noqa: ANN001, ANN202
                saved.append((target, result))

        with patch(_HSR_PATH, _FakeRepo):
            ScoringService().compute_hardening_score()

        assert saved == []

    def test_persistenz_fehler_bricht_score_nicht(self):
        class _FakeRepo:
            def save_score(self, target, result, *, subject_id=""):  # noqa: ANN001, ANN202
                raise OSError("Disk weg")

        with patch(_HSR_PATH, _FakeRepo):
            # Fail-soft: darf nicht werfen.
            result = ScoringService().compute_hardening_score(target_name="X")

        assert result is not None

    def test_lade_hardening_verlauf_durchreichung(self):
        rows = [("2026-06-03T10:00:00", 85.0), ("2026-06-02T10:00:00", 82.0)]

        class _FakeRepo:
            def load_history(self, target, *, limit=20):  # noqa: ANN001, ANN202
                return rows

        with patch(_HSR_PATH, _FakeRepo):
            verlauf = ScoringService().lade_hardening_verlauf("X", limit=5)

        assert verlauf == rows

    def test_lade_hardening_verlauf_fehler_leer(self):
        class _FakeRepo:
            def load_history(self, target, *, limit=20):  # noqa: ANN001, ANN202
                raise OSError("DB weg")

        with patch(_HSR_PATH, _FakeRepo):
            assert ScoringService().lade_hardening_verlauf("X") == []

    def test_previous_hardening_score_liest_tuple(self):
        class _FakeRepo:
            def load_history(self, target, *, limit=20):  # noqa: ANN001, ANN202
                # neueste zuerst: [0]=90 (current), [1]=80 (previous)
                return [("t2", 90.0), ("t1", 80.0)]

        with patch(_HSR_PATH, _FakeRepo):
            assert ScoringService().previous_hardening_score("X") == 80.0

    def test_lade_letztes_hardening_result_durchreichung(self):
        """: Wrapper reicht das rehydrierte Result durch (application-API)."""
        sentinel = object()

        class _FakeRepo:
            def load_latest_result(self, target_name=None):  # noqa: ANN001, ANN202
                return sentinel

        with patch(_HSR_PATH, _FakeRepo):
            assert ScoringService().lade_letztes_hardening_result() is sentinel

    def test_lade_letztes_hardening_result_fehler_none(self):
        """: korruptes data_json (ValueError) → fail-soft None."""

        class _FakeRepo:
            def load_latest_result(self, target_name=None):  # noqa: ANN001, ANN202
                raise ValueError("korruptes data_json")

        with patch(_HSR_PATH, _FakeRepo):
            assert ScoringService().lade_letztes_hardening_result() is None


class TestScoreRepository:
    def test_speichere_und_lade(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            score = _make_security_score("Mustermann GmbH", 78.0)
            repo.speichere_score(score)

            geladen = repo.lade_letzte_scores("Mustermann GmbH", limit=5)
        assert len(geladen) == 1
        assert geladen[0].id == score.id
        assert geladen[0].overall_score == pytest.approx(78.0)
        assert geladen[0].grade == "B"

    def test_lade_leere_db(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            result = repo.lade_letzte_scores("Unbekannt", limit=5)
        assert result == []

    def test_bekannte_targets(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            repo.speichere_score(_make_security_score("Alpha AG", 80.0))
            repo.speichere_score(_make_security_score("Beta GmbH", 60.0))
            repo.speichere_score(_make_security_score("Alpha AG", 75.0))

            targets = repo.lade_bekannte_targets()
        assert targets == ["Alpha AG", "Beta GmbH"]

    def test_limit_wird_eingehalten(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            for i in range(5):
                repo.speichere_score(_make_security_score("X", float(50 + i)))

            result = repo.lade_letzte_scores("X", limit=3)
        assert len(result) == 3

    def test_neueste_zuerst(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            s1 = _make_security_score("X", 40.0)
            s1_ts = "2026-03-01T10:00:00+00:00"
            s2 = _make_security_score("X", 80.0)
            s2_ts = "2026-04-01T10:00:00+00:00"

            import dataclasses

            s1 = dataclasses.replace(s1, timestamp=s1_ts)
            s2 = dataclasses.replace(s2, timestamp=s2_ts)

            repo.speichere_score(s1)
            repo.speichere_score(s2)

            result = repo.lade_letzte_scores("X", limit=10)
        # Neueste zuerst
        assert result[0].overall_score == pytest.approx(80.0)
        assert result[1].overall_score == pytest.approx(40.0)

    def test_komponenten_werden_persistiert(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            score = _make_security_score("X", 72.0)
            repo.speichere_score(score)
            geladen = repo.lade_letzte_scores("X")[0]

        assert len(geladen.components) == 1
        assert geladen.components[0].source_tool == "api_security"
        assert geladen.components[0].findings_high == 1

    def test_loesche_scores_vor(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = ScoreRepository()
            import dataclasses

            s_alt = dataclasses.replace(
                _make_security_score("X", 60.0),
                timestamp="2026-01-01T00:00:00+00:00",
            )
            s_neu = dataclasses.replace(
                _make_security_score("X", 80.0),
                timestamp="2026-04-01T00:00:00+00:00",
            )
            repo.speichere_score(s_alt)
            repo.speichere_score(s_neu)

            geloescht = repo.loesche_scores_vor("2026-02-01T00:00:00+00:00")
            assert geloescht == 1

            verbleibend = repo.lade_letzte_scores("X")
        assert len(verbleibend) == 1
        assert verbleibend[0].overall_score == pytest.approx(80.0)


# ---------------------------------------------------------------------------
# PDF-Report Generator
# ---------------------------------------------------------------------------


def _make_score_with_components(
    target: str = "Test GmbH",
    overall: float = 72.0,
) -> SecurityScore:
    """Erzeugt einen vollständigen SecurityScore mit Komponenten für PDF-Tests."""
    return SecurityScore(
        id=str(uuid.uuid4()),
        target_name=target,
        timestamp=datetime.now(UTC).isoformat(),
        overall_score=overall,
        grade=score_to_grade(overall),
        components=[
            ScoreComponent(
                name="API Security",
                score=78.0,
                weight=DEFAULT_WEIGHTS["api_security"],
                findings_critical=0,
                findings_high=2,
                findings_medium=1,
                last_scan="2026-04-02T10:00:00+00:00",
                source_tool="api_security",
            ),
            ScoreComponent(
                name="Netzwerk",
                score=50.0,
                weight=DEFAULT_WEIGHTS["network_scanner"],
                findings_critical=2,
                findings_high=0,
                findings_medium=0,
                last_scan="2026-04-02T09:00:00+00:00",
                source_tool="network_scanner",
            ),
        ],
        summary=f"Score {overall:.0f}/100 — 2 kritische Findings.",
    )


class TestSecurityReportGenerator:
    def test_generate_erstellt_datei(self, tmp_path):
        """PDF-Datei wird erzeugt und ist nicht leer."""
        score = _make_score_with_components()
        out = str(tmp_path / "report.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out)

        import os

        assert os.path.exists(out)
        assert os.path.getsize(out) > 1000  # Mindestens 1 KB

    def test_generate_gueltige_pdf_header(self, tmp_path):
        """Datei beginnt mit PDF-Magic-Bytes."""
        score = _make_score_with_components()
        out = str(tmp_path / "report.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out)

        with open(out, "rb") as f:
            header = f.read(5)
        assert header == b"%PDF-"

    def test_generate_ohne_details(self, tmp_path):
        """PDF wird auch ohne Detail-Seiten generiert."""
        score = _make_score_with_components()
        out = str(tmp_path / "report_no_details.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out, include_details=False)

        import os

        assert os.path.exists(out)
        assert os.path.getsize(out) > 500

    def test_generate_ohne_verlauf(self, tmp_path):
        """PDF funktioniert ohne Verlaufs-Daten (leere Liste)."""
        score = _make_score_with_components()
        out = str(tmp_path / "report_no_history.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out, verlauf=[])
        import os

        assert os.path.exists(out)

    def test_generate_mit_verlauf(self, tmp_path):
        """PDF mit Verlaufs-Trend wird ohne Fehler generiert."""
        score = _make_score_with_components()
        verlauf = [
            _make_score_with_components(overall=72.0),
            _make_score_with_components(overall=65.0),
            _make_score_with_components(overall=58.0),
        ]
        out = str(tmp_path / "report_with_history.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out, verlauf=verlauf)
        import os

        assert os.path.getsize(out) > 1000

    def test_generate_ausgabeverzeichnis_wird_erstellt(self, tmp_path):
        """Fehlende Unterordner werden automatisch erstellt."""
        score = _make_score_with_components()
        out = str(tmp_path / "neu" / "tief" / "report.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out)
        import os

        assert os.path.exists(out)

    def test_generate_leere_komponenten(self, tmp_path):
        """PDF funktioniert auch wenn der Score keine Komponenten hat."""
        score = SecurityScore(
            id=str(uuid.uuid4()),
            target_name="Leer GmbH",
            timestamp=datetime.now(UTC).isoformat(),
            overall_score=0.0,
            grade="F",
            components=[],
            summary="Kein Scan-Ergebnis.",
        )
        out = str(tmp_path / "report_empty.pdf")
        gen = SecurityReportGenerator()
        gen.generate(score, out)
        import os

        assert os.path.exists(out)


class TestBuildPriorities:
    def test_keine_findings_keine_prioritaeten(self):
        score = SecurityScore(
            id="x",
            target_name="X",
            timestamp="2026-04-02T10:00:00+00:00",
            overall_score=100.0,
            grade="A",
            components=[
                ScoreComponent("API", 100.0, 0.3, 0, 0, 0),
            ],
        )
        prios = _build_priorities(score)
        assert prios == []

    def test_kritisch_vor_hoch(self):
        score = SecurityScore(
            id="x",
            target_name="X",
            timestamp="2026-04-02T10:00:00+00:00",
            overall_score=50.0,
            grade="D",
            components=[
                ScoreComponent("API", 50.0, 0.3, findings_high=1, findings_critical=0),
                ScoreComponent(
                    "Netz", 25.0, 0.25, findings_critical=1, findings_high=0
                ),
            ],
        )
        prios = _build_priorities(score)
        # Kritisch zuerst
        assert prios[0][1] == "KRITISCH"

    def test_alle_schweregrade_enthalten(self):
        score = SecurityScore(
            id="x",
            target_name="X",
            timestamp="2026-04-02T10:00:00+00:00",
            overall_score=30.0,
            grade="F",
            components=[
                ScoreComponent(
                    "API",
                    30.0,
                    0.3,
                    findings_critical=1,
                    findings_high=1,
                    findings_medium=1,
                ),
            ],
        )
        prios = _build_priorities(score)
        severities = [p[1] for p in prios]
        assert "KRITISCH" in severities
        assert "HOCH" in severities
        assert "MITTEL" in severities


class TestFindingDescription:
    def test_bekannte_kombination_network_kritisch(self):
        desc = _finding_description("network_scanner", "KRITISCH", 2)
        assert "RDP" in desc or "Port" in desc or "Netzwerk" in desc

    def test_unbekannte_kombination_fallback(self):
        desc = _finding_description("unbekannt_tool", "KRITISCH", 3)
        assert "3" in desc
        assert "KRITISCH" in desc
