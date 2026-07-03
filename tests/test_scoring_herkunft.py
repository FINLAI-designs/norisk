"""Tests für A+B Schritt 1–4: Provenance (Herkunft) im Security-Scoring.

Deckt ab:
- Domain: ``herkunft`` an HardeningScoreResult/SecurityScore (Default GEMESSEN),
  Durchreichung in ``compute_hardening_score``.
- Persistenz: Round-Trip der ``herkunft``-Spalte in beiden Repos.
- P0-A: ``load_latest_measured_result`` filtert ERFASST-Kundeneintraege weg.
- P0-B: Mode-Gate ``assert_messung_nur_self`` + Service-Backstop.
"""

from __future__ import annotations

import pytest

from core.herkunft import Herkunft
from core.security_subject.models import SubjectKind
from tools.security_scoring.domain.hardening_score import compute_hardening_score
from tools.security_scoring.domain.mode_gate import (
    ScoringModeViolationError,
    assert_messung_nur_self,
)
from tools.security_scoring.domain.models import ScoreComponent, SecurityScore


def _comp() -> ScoreComponent:
    return ScoreComponent(name="X", score=80.0, weight=0.5, source_tool="cve_exposure")


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class TestDomainHerkunft:
    def test_hardening_default_gemessen(self) -> None:
        assert compute_hardening_score([_comp()]).herkunft is Herkunft.GEMESSEN

    def test_hardening_durchreichung_erfasst(self) -> None:
        res = compute_hardening_score([_comp()], herkunft=Herkunft.ERFASST)
        assert res.herkunft is Herkunft.ERFASST

    def test_hardening_leerer_pfad_durchreichung(self) -> None:
        # Auch der "keine aktiven Daten"-Frueh-Return traegt die Herkunft.
        leer = ScoreComponent(
            name="Y", score=0.0, weight=0.5, source_tool="cve_exposure",
            data_available=False,
        )
        res = compute_hardening_score([leer], herkunft=Herkunft.ERFASST)
        assert res.herkunft is Herkunft.ERFASST

    def test_security_score_default_gemessen(self) -> None:
        s = SecurityScore(
            id="s1", target_name="X", timestamp="2026-06-01T10:00:00+00:00",
            overall_score=70.0, grade="C",
        )
        assert s.herkunft is Herkunft.GEMESSEN


# ---------------------------------------------------------------------------
# Mode-Gate (P0-B) — pure
# ---------------------------------------------------------------------------


class TestModeGate:
    def test_gemessen_fuer_kunde_verboten(self) -> None:
        with pytest.raises(ScoringModeViolationError):
            assert_messung_nur_self(Herkunft.GEMESSEN, SubjectKind.KUNDE)

    def test_erfasst_fuer_kunde_erlaubt(self) -> None:
        assert_messung_nur_self(Herkunft.ERFASST, SubjectKind.KUNDE)  # kein Raise

    def test_gemessen_fuer_eigenes_erlaubt(self) -> None:
        assert_messung_nur_self(Herkunft.GEMESSEN, SubjectKind.EIGENES)

    def test_unbekanntes_subjekt_erlaubt(self) -> None:
        # None = kein SubjectStore / leeres subject_id = eigenes System.
        assert_messung_nur_self(Herkunft.GEMESSEN, None)


# ---------------------------------------------------------------------------
# Persistenz — Round-Trip + P0-A-Filter (nutzt isolierte tmp-DB via conftest)
# ---------------------------------------------------------------------------


class TestHardeningRepoHerkunft:
    def test_roundtrip_und_p0a_filter(self) -> None:
        from tools.security_scoring.data.hardening_score_repository import (
            HardeningScoreRepository,
        )

        repo = HardeningScoreRepository()
        gemessen = compute_hardening_score([_comp()], herkunft=Herkunft.GEMESSEN)
        erfasst = compute_hardening_score([_comp()], herkunft=Herkunft.ERFASST)

        # Eigenes (gemessen, aelter) + Kunde (erfasst, NEUER).
        repo.save_score(
            "Eigenes", gemessen,
            timestamp="2026-06-01T10:00:00+00:00", subject_id="self",
        )
        repo.save_score(
            "Kunde GmbH", erfasst,
            timestamp="2026-06-28T10:00:00+00:00", subject_id="cust-1",
        )

        # Ungefiltert: der global juengste ist der Kunden-Eintrag (erfasst).
        latest = repo.load_latest_result()
        assert latest is not None
        assert latest.herkunft is Herkunft.ERFASST

        # P0-A: measured-only ueberspringt den neueren Kunden-Eintrag.
        measured = repo.load_latest_measured_result()
        assert measured is not None
        assert measured.herkunft is Herkunft.GEMESSEN
        assert measured.overall_score == gemessen.overall_score

    def test_measured_leer_ohne_gemessenen(self) -> None:
        from tools.security_scoring.data.hardening_score_repository import (
            HardeningScoreRepository,
        )

        repo = HardeningScoreRepository()
        repo.save_score(
            "Kunde GmbH",
            compute_hardening_score([_comp()], herkunft=Herkunft.ERFASST),
            subject_id="cust-1",
        )
        assert repo.load_latest_measured_result() is None


class TestScoreRepoHerkunft:
    def test_roundtrip_erfasst(self) -> None:
        from tools.security_scoring.data.score_repository import ScoreRepository

        repo = ScoreRepository()
        score = SecurityScore(
            id="s1", target_name="Kunde", timestamp="2026-06-01T10:00:00+00:00",
            overall_score=70.0, grade="C", herkunft=Herkunft.ERFASST,
        )
        repo.speichere_score(score)
        loaded = repo.lade_letzte_scores("Kunde", limit=1)
        assert loaded and loaded[0].herkunft is Herkunft.ERFASST

    def test_roundtrip_default_gemessen(self) -> None:
        from tools.security_scoring.data.score_repository import ScoreRepository

        repo = ScoreRepository()
        repo.speichere_score(
            SecurityScore(
                id="s2", target_name="Eigenes",
                timestamp="2026-06-01T10:00:00+00:00", overall_score=90.0, grade="A",
            )
        )
        loaded = repo.lade_letzte_scores("Eigenes", limit=1)
        assert loaded and loaded[0].herkunft is Herkunft.GEMESSEN


# ---------------------------------------------------------------------------
# Service-Backstop (P0-B) — Persist-Gate
# ---------------------------------------------------------------------------


class _FakeSubject:
    def __init__(self, kind: SubjectKind) -> None:
        self.kind = kind


class _FakeStore:
    def __init__(self, kind: SubjectKind) -> None:
        self._subj = _FakeSubject(kind)

    def get(self, subject_id: str):  # noqa: ANN201, ARG002 — Duck-Typed Port-Stub
        return self._subj


class TestServiceBackstop:
    def test_gemessen_persist_fuer_kunde_raised(self) -> None:
        from tools.security_scoring.application.scoring_service import ScoringService

        service = ScoringService(subject_store=_FakeStore(SubjectKind.KUNDE))
        gemessen = compute_hardening_score([_comp()], herkunft=Herkunft.GEMESSEN)
        with pytest.raises(ScoringModeViolationError):
            service._persistiere_hardening_score(  # noqa: SLF001
                "Kunde GmbH", gemessen, subject_id="cust-1"
            )

    def test_erfasst_persist_fuer_kunde_ok(self) -> None:
        from tools.security_scoring.application.scoring_service import ScoringService

        service = ScoringService(subject_store=_FakeStore(SubjectKind.KUNDE))
        erfasst = compute_hardening_score([_comp()], herkunft=Herkunft.ERFASST)
        # Kein Raise — ERFASST fuer Kunde ist der erlaubte Pfad (persistiert).
        service._persistiere_hardening_score(  # noqa: SLF001
            "Kunde GmbH", erfasst, subject_id="cust-1"
        )
