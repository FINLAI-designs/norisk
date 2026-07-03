"""Tests für Phase D: Hardening-Score-Query (Scoring-Wert im Kunden-PDF)."""

from __future__ import annotations

from core.herkunft import Herkunft
from core.security_subject.models import SubjectKind


class _Subj:
    def __init__(self, kind: SubjectKind) -> None:
        self.kind = kind


class _Store:
    def __init__(self, kind: SubjectKind) -> None:
        self._s = _Subj(kind)

    def get(self, subject_id: str):  # noqa: ANN201, ARG002
        return self._s


def test_adapter_round_trip() -> None:
    from tools.security_scoring.application.hardening_query_adapter import (
        ScoringHardeningQuery,
    )
    from tools.security_scoring.application.scoring_service import ScoringService

    svc = ScoringService(subject_store=_Store(SubjectKind.KUNDE))
    svc.erfasse_kunden_hardening("cust-1", {"firewall": True, "backup": True})

    q = ScoringHardeningQuery()
    res = q.overall_by_subject("cust-1")
    assert res is not None
    score, herkunft = res
    assert 0 <= score <= 100
    assert herkunft == Herkunft.ERFASST.value  # "erfasst"
    assert q.overall_by_subject("unbekannt") is None
    assert q.overall_by_subject("") is None


def test_resolver_liefert_query() -> None:
    from core.hardening_query import create_hardening_score_query

    q = create_hardening_score_query()
    assert q is not None
    assert hasattr(q, "overall_by_subject")


def test_use_case_fetch_fail_soft(monkeypatch) -> None:  # noqa: ANN001
    from tools.customer_audit.application.generate_report_use_case import (
        GenerateReportUseCase,
    )

    # Leeres subject_id -> kein Abruf.
    assert GenerateReportUseCase._fetch_hardening("") == (None, "")
    # Resolver None (fail-soft) -> (None, "").
    monkeypatch.setattr(
        "core.hardening_query.create_hardening_score_query", lambda: None
    )
    assert GenerateReportUseCase._fetch_hardening("x") == (None, "")
