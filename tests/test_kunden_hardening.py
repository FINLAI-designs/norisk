"""Tests für Schritt 5–6: subjekt-fähige Reads, IDOR-Fix, Kunden-Erfassung."""

from __future__ import annotations

import pytest

from core.herkunft import Herkunft
from core.security_subject.models import SubjectKind
from tools.security_scoring.application.kunden_hardening import (
    KUNDEN_HARDENING_FACTS,
    facts_to_components,
)
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.domain.hardening_score import compute_hardening_score
from tools.security_scoring.domain.mode_gate import ScoringModeViolationError
from tools.security_scoring.domain.models import ScoreComponent


class _Subj:
    def __init__(self, kind: SubjectKind) -> None:
        self.kind = kind


class _Store:
    def __init__(self, kind: SubjectKind) -> None:
        self._s = _Subj(kind)

    def get(self, subject_id: str):  # noqa: ANN201, ARG002
        return self._s


def _comp(score: float = 80.0) -> ScoreComponent:
    return ScoreComponent(
        name="X", score=score, weight=0.5, source_tool="cve_exposure"
    )


class TestFactsToComponents:
    def test_alle_true_100(self) -> None:
        comps = facts_to_components({k: True for k, _ in KUNDEN_HARDENING_FACTS})
        assert len(comps) == 1
        assert comps[0].data_available is True
        assert comps[0].score == 100.0

    def test_gemischt_50(self) -> None:
        comps = facts_to_components({"firewall": True, "backup": False})
        assert comps[0].score == 50.0
        assert comps[0].findings_high == 1

    def test_none_und_unbekannt_ignoriert(self) -> None:
        comps = facts_to_components({"firewall": None, "blah": True})
        assert comps[0].data_available is False


class TestErfasseKundenHardening:
    def test_kunde_persistiert_erfasst(self) -> None:
        svc = ScoringService(subject_store=_Store(SubjectKind.KUNDE))
        res = svc.erfasse_kunden_hardening(
            "cust-1", {"firewall": True, "backup": True}
        )
        assert res.herkunft is Herkunft.ERFASST
        # subjekt-keyed Round-Trip (target_name = subject_id, kein PII).
        geladen = svc.lade_letztes_hardening_result_by_subject("cust-1")
        assert geladen is not None
        assert geladen.herkunft is Herkunft.ERFASST

    def test_self_subjekt_abgelehnt(self) -> None:
        svc = ScoringService(subject_store=_Store(SubjectKind.EIGENES))
        with pytest.raises(ScoringModeViolationError):
            svc.erfasse_kunden_hardening("self", {"firewall": True})

    def test_ohne_store_abgelehnt(self) -> None:
        svc = ScoringService()  # kein subject_store -> kind None -> abgelehnt
        with pytest.raises(ScoringModeViolationError):
            svc.erfasse_kunden_hardening("x", {"firewall": True})


class TestHardeningSubjektReads:
    def _repo(self):  # noqa: ANN202
        from tools.security_scoring.data.hardening_score_repository import (
            HardeningScoreRepository,
        )

        return HardeningScoreRepository()

    def test_isolation_und_leeres_subjekt(self) -> None:
        repo = self._repo()
        repo.save_score(
            "a", compute_hardening_score([_comp()]),
            timestamp="2026-06-01T00:00:00+00:00", subject_id="A",
        )
        repo.save_score(
            "b", compute_hardening_score([_comp()]),
            timestamp="2026-06-02T00:00:00+00:00", subject_id="B",
        )
        assert repo.load_latest_result_by_subject("A") is not None
        assert len(repo.load_history_by_subject("A")) == 1
        assert repo.load_latest_result_by_subject("") is None

    def test_trend_zeigt_veraenderung(self) -> None:
        repo = self._repo()
        repo.save_score(
            "a", compute_hardening_score([_comp(60)]),
            timestamp="2026-06-01T00:00:00+00:00", subject_id="A",
        )
        repo.save_score(
            "a", compute_hardening_score([_comp(90)]),
            timestamp="2026-06-02T00:00:00+00:00", subject_id="A",
        )
        two = repo.get_last_two_scores_by_subject("A")
        assert two is not None
        prev, cur = two
        assert cur > prev  # sichtbare Veränderung im Zeitverlauf


class TestOrgAssessmentIdorFix:
    def _assessment(self, audit_id: str):  # noqa: ANN202
        from tools.security_scoring.domain.org_security import (
            METRIK_DSGVO,
            METRIK_MFA,
            METRIK_PASSWORT_MANAGER,
            METRIK_PHISHING,
            OrgAssessment,
            OrgMetrikErgebnis,
        )

        def m(k: str) -> OrgMetrikErgebnis:
            return OrgMetrikErgebnis(metrik=k, antworten={})

        return OrgAssessment(
            audit_id=audit_id, timestamp="2026-06-01T00:00:00+00:00",
            dsgvo=m(METRIK_DSGVO), phishing=m(METRIK_PHISHING),
            mfa=m(METRIK_MFA), passwort_manager=m(METRIK_PASSWORT_MANAGER),
        )

    def test_subjekt_filter_isoliert(self) -> None:
        from tools.security_scoring.data.org_assessment_repository import (
            OrgAssessmentRepository,
        )

        repo = OrgAssessmentRepository()
        repo.speichere(self._assessment("aud-1"))
        repo.set_subject_id("aud-1", "A")
        assert repo.lade_letztes_by_subject("A") is not None
        assert repo.lade_letztes_by_subject("B") is None  # IDOR: kein Cross-Leak
        assert repo.lade_letztes_by_subject("") is None
