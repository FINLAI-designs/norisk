"""
test_customer_audit_risk.

Tests fuer die BSI-200-3-Risiko-Bewertung (Domain + Repo + Service).
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.customer_audit.application.risk_assessment_service import (
    RiskAssessmentService,
)
from tools.customer_audit.data.risk_assessment_repository import (
    DbRiskAssessmentRepository,
)
from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG,
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskAssessment,
    RiskCategory,
    RiskImpact,
    RiskLevel,
    RiskProbability,
    risk_score_matrix,
)


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


# ---------------------------------------------------------------------------
# Domain — Level-Ableitung
# ---------------------------------------------------------------------------


class TestRiskLevel:
    @pytest.mark.parametrize(
        "prob,impact,expected",
        [
            (RiskProbability.SELTEN, RiskImpact.VERNACHLAESSIGBAR, RiskLevel.GERING),  # 1
            (RiskProbability.SELTEN, RiskImpact.BEGRENZT, RiskLevel.GERING),  # 2
            (RiskProbability.SELTEN, RiskImpact.BETRAECHTLICH, RiskLevel.GERING),  # 3
            (RiskProbability.MITTEL, RiskImpact.BEGRENZT, RiskLevel.MITTEL),  # 4
            (RiskProbability.MITTEL, RiskImpact.BETRAECHTLICH, RiskLevel.MITTEL),  # 6
            (RiskProbability.HAEUFIG, RiskImpact.BETRAECHTLICH, RiskLevel.HOCH),  # 9
            (RiskProbability.HAEUFIG, RiskImpact.EXISTENZBEDROHEND, RiskLevel.SEHR_HOCH),  # 12
            (RiskProbability.SEHR_HAEUFIG, RiskImpact.EXISTENZBEDROHEND, RiskLevel.SEHR_HOCH),  # 16
        ],
    )
    def test_from_score(
        self, prob: RiskProbability, impact: RiskImpact, expected: RiskLevel
    ) -> None:
        assert RiskLevel.from_score(prob, impact) is expected


class TestRiskMatrix:
    def test_4x4(self) -> None:
        matrix = risk_score_matrix()
        assert len(matrix) == 4
        assert all(len(row) == 4 for row in matrix)
        # Eckwerte
        assert matrix[0][0] == 1
        assert matrix[3][3] == 16
        # Symmetrie (Multiplikation kommutativ)
        for i in range(4):
            for j in range(4):
                assert matrix[i][j] == matrix[j][i]


class TestRiskCatalog:
    def test_10_default_risks(self) -> None:
        assert len(DEFAULT_RISK_CATALOG) == 10

    def test_eindeutige_keys(self) -> None:
        keys = [r.key for r in DEFAULT_RISK_CATALOG]
        assert len(keys) == len(set(keys))

    def test_lookup_map_konsistent(self) -> None:
        for r in DEFAULT_RISK_CATALOG:
            assert DEFAULT_RISK_CATALOG_BY_KEY[r.key] is r

    def test_alle_kategorien_vertreten(self) -> None:
        cats = {r.category for r in DEFAULT_RISK_CATALOG}
        # Konzept §5.2 fordert breite Kategorien-Abdeckung — wir checken
        # dass mindestens 5 der 6 Kategorien dabei sind.
        assert len(cats) >= 5


class TestRiskAssessment:
    def test_custom_braucht_titel_und_kategorie(self) -> None:
        with pytest.raises(ValueError, match="custom_title"):
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="",
                probability=RiskProbability.MITTEL,
                impact=RiskImpact.BEGRENZT,
                custom_category=RiskCategory.CYBER,
                is_custom=True,
            )

    def test_default_braucht_catalog_key(self) -> None:
        with pytest.raises(ValueError, match="catalog_key ist Pflicht"):
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="",
                probability=RiskProbability.MITTEL,
                impact=RiskImpact.BEGRENZT,
                is_custom=False,
            )

    def test_custom_schliesst_catalog_key_aus(self) -> None:
        with pytest.raises(ValueError, match="schliesst catalog_key aus"):
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="ransomware",
                probability=RiskProbability.HAEUFIG,
                impact=RiskImpact.EXISTENZBEDROHEND,
                custom_title="Sonderfall",
                custom_category=RiskCategory.CYBER,
                is_custom=True,
            )

    def test_level_aggregation(self) -> None:
        a = RiskAssessment(
            id=None,
            audit_id="a1",
            catalog_key="ransomware",
            probability=RiskProbability.HAEUFIG,
            impact=RiskImpact.EXISTENZBEDROHEND,
        )
        assert a.level is RiskLevel.SEHR_HOCH

    def test_display_title_aus_catalog(self) -> None:
        a = RiskAssessment(
            id=None,
            audit_id="a1",
            catalog_key="ransomware",
            probability=RiskProbability.MITTEL,
            impact=RiskImpact.BETRAECHTLICH,
        )
        assert "Ransomware" in a.display_title(DEFAULT_RISK_CATALOG_BY_KEY)


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


@pytest.fixture
def repo() -> DbRiskAssessmentRepository:
    return DbRiskAssessmentRepository(db=_InMemoryDB())


class TestRepository:
    def test_upsert_und_load(self, repo: DbRiskAssessmentRepository) -> None:
        items = [
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key=entry.key,
                probability=entry.default_probability,
                impact=entry.default_impact,
            )
            for entry in DEFAULT_RISK_CATALOG
        ]
        repo.upsert_for_audit("a1", items)
        loaded = repo.list_for_audit("a1")
        assert len(loaded) == 10

    def test_replace_ueberschreibt_atomar(
        self, repo: DbRiskAssessmentRepository
    ) -> None:
        first = [
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="ransomware",
                probability=RiskProbability.MITTEL,
                impact=RiskImpact.BETRAECHTLICH,
            )
        ]
        repo.upsert_for_audit("a1", first)
        assert len(repo.list_for_audit("a1")) == 1

        replacement = [
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="phishing",
                probability=RiskProbability.HAEUFIG,
                impact=RiskImpact.BEGRENZT,
            )
        ]
        repo.upsert_for_audit("a1", replacement)
        loaded = repo.list_for_audit("a1")
        assert len(loaded) == 1
        assert loaded[0].catalog_key == "phishing"

    def test_delete_for_audit(self, repo: DbRiskAssessmentRepository) -> None:
        items = [
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="ransomware",
                probability=RiskProbability.MITTEL,
                impact=RiskImpact.BEGRENZT,
            )
        ]
        repo.upsert_for_audit("a1", items)
        assert repo.delete_for_audit("a1") == 1

    def test_sortierung_score_desc(
        self, repo: DbRiskAssessmentRepository
    ) -> None:
        items = [
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="ransomware",
                probability=RiskProbability.SELTEN,
                impact=RiskImpact.VERNACHLAESSIGBAR,
            ),
            RiskAssessment(
                id=None,
                audit_id="a1",
                catalog_key="phishing",
                probability=RiskProbability.SEHR_HAEUFIG,
                impact=RiskImpact.EXISTENZBEDROHEND,
            ),
        ]
        repo.upsert_for_audit("a1", items)
        loaded = repo.list_for_audit("a1")
        # Phishing (16) muss vor Ransomware (1) stehen.
        assert loaded[0].catalog_key == "phishing"
        assert loaded[1].catalog_key == "ransomware"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> RiskAssessmentService:
    return RiskAssessmentService(repository=DbRiskAssessmentRepository(db=_InMemoryDB()))


class TestService:
    def test_initialize_defaults_legt_10_an(
        self, service: RiskAssessmentService
    ) -> None:
        result = service.initialize_defaults("a1")
        assert len(result) == 10

    def test_initialize_defaults_idempotent(
        self, service: RiskAssessmentService
    ) -> None:
        first = service.initialize_defaults("a1")
        second = service.initialize_defaults("a1")
        # Zweiter Aufruf liefert die bereits existierenden Items, nicht neue.
        assert len(first) == len(second) == 10

    def test_summary_aggregiert_levels(
        self, service: RiskAssessmentService
    ) -> None:
        service.initialize_defaults("a1")
        summary = service.summary("a1")
        assert summary.total_count == 10
        assert summary.accepted_count == 0
        # Top-3 muessen die hoechsten Scores haben.
        assert len(summary.top_risks) == 3
        scores = [r.probability.value * r.impact.value for r in summary.top_risks]
        assert scores == sorted(scores, reverse=True)

    def test_summary_accepted_count(self, service: RiskAssessmentService) -> None:
        service.initialize_defaults("a1")
        items = service.load("a1")
        from dataclasses import replace as dc_replace  # noqa: PLC0415

        # 2 Items akzeptieren
        modified = [
            dc_replace(item, is_accepted=True) if idx < 2 else item
            for idx, item in enumerate(items)
        ]
        service.replace("a1", modified)
        summary = service.summary("a1")
        assert summary.accepted_count == 2
