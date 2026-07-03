"""Tests fuer die SELF-Audit-Application-Fassade / Review-Fix).

Sichert den fail-closed SELF-Gate ab: nur AuditMode.SELF wird zurueckgegeben.
"""

from __future__ import annotations

from types import SimpleNamespace

from tools.customer_audit.application.self_audit_query import (
    lade_self_audit_result,
    lade_top_risiken,
)
from tools.customer_audit.domain.entities import AuditMode


class _FakeRepo:
    def __init__(self, audit: object | None, *, summary: dict | None = None) -> None:
        self._audit = audit
        self._summary = (
            summary
            if summary is not None
            else ({"audit_id": "a1"} if audit is not None else None)
        )

    def latest_summary_by_subject(self, subject_id: str) -> dict | None:
        return self._summary

    def load_by_id(self, audit_id: str) -> object | None:
        return self._audit


def test_self_audit_wird_zurueckgegeben() -> None:
    audit = SimpleNamespace(audit_mode=AuditMode.SELF, overall_score=80.0)
    assert lade_self_audit_result("subj", repo=_FakeRepo(audit)) is audit


def test_customer_audit_wird_blockiert() -> None:
    audit = SimpleNamespace(audit_mode=AuditMode.CUSTOMER, overall_score=80.0)
    assert lade_self_audit_result("subj", repo=_FakeRepo(audit)) is None


def test_leeres_subjekt_ist_none() -> None:
    assert lade_self_audit_result("", repo=_FakeRepo(None)) is None


def test_kein_audit_ist_none() -> None:
    assert lade_self_audit_result("subj", repo=_FakeRepo(None)) is None


def test_summary_ohne_audit_id_ist_none() -> None:
    repo = _FakeRepo(SimpleNamespace(audit_mode=AuditMode.SELF), summary={})
    assert lade_self_audit_result("subj", repo=repo) is None


# --- BSI-Top-Risiken (Phase 4b) -------------------------------------------


class _FakeRiskSvc:
    def __init__(self, top: list) -> None:
        self._top = top

    def summary(self, audit_id: str) -> SimpleNamespace:
        return SimpleNamespace(top_risks=self._top)


def _risk(titel: str, level_label: str) -> SimpleNamespace:
    return SimpleNamespace(
        is_custom=True,
        custom_title=titel,
        catalog_key="",
        level=SimpleNamespace(label=lambda lbl=level_label: lbl),
    )


def test_top_risiken_leer_ohne_audit_id() -> None:
    assert lade_top_risiken("") == ()


def test_top_risiken_mappt_titel_und_level() -> None:
    svc = _FakeRiskSvc([_risk("Ransomware", "sehr hoch"), _risk("Phishing", "hoch")])
    assert lade_top_risiken("a1", service=svc) == (
        ("Ransomware", "sehr hoch"),
        ("Phishing", "hoch"),
    )


def test_top_risiken_unbekannter_katalog_key_faellt_zurueck() -> None:
    r = SimpleNamespace(
        is_custom=False,
        catalog_key="gibt_es_nicht_xyz",
        custom_title="",
        level=SimpleNamespace(label=lambda: "hoch"),
    )
    assert lade_top_risiken("a1", service=_FakeRiskSvc([r])) == (
        ("gibt_es_nicht_xyz", "hoch"),
    )
