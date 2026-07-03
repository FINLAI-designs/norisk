"""test_workflow_service — Anwendungslogik des Cockpit-Workflow-Tabs, Phase 2).

Deckt das Subjekt-Gating (SELF vs. Kunde, W1-Profil) + den Merge von Definition
und Fortschritt ab. Nutzt das echte Repository gegen einen In-Memory-SQLite-Stub
(kein GUI, kein SQLCipher).
"""

from __future__ import annotations

import sqlite3

import pytest

from core.security_subject.models import Subject, SubjectKind
from tools.norisk_dashboard.application.workflow_service import WorkflowService
from tools.norisk_dashboard.data.workflow_progress_repository import (
    WorkflowProgressRepository,
)
from tools.norisk_dashboard.domain.workflow_models import WorkflowStepStatus


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


@pytest.fixture
def repo() -> WorkflowProgressRepository:
    return WorkflowProgressRepository(db=_InMemoryDB())


def _self_subject(
    website: int | None = None, api: int | None = None, dev: int | None = None
) -> Subject:
    return Subject(
        subject_id="self-1",
        kind=SubjectKind.EIGENES,
        name="Mein System",
        hat_eigene_website=website,
        hat_eigene_api=api,
        ist_entwickler=dev,
    )


def _kunde() -> Subject:
    return Subject(subject_id="kunde-1", kind=SubjectKind.KUNDE, name="Muster GmbH")


def _keys(service: WorkflowService, subject: Subject) -> set[str]:
    return {s.step_key for s in service.steps_for_subject(subject)}


class TestGating:
    def test_self_ohne_flags_zeigt_alle_14(self, repo) -> None:
        svc = WorkflowService(repo)
        assert len(svc.steps_for_subject(_self_subject())) == 14

    def test_website_0_blendet_cert_aus(self, repo) -> None:
        svc = WorkflowService(repo)
        assert "self_scan_cert" not in _keys(svc, _self_subject(website=0))

    def test_api_0_blendet_api_aus(self, repo) -> None:
        svc = WorkflowService(repo)
        assert "self_scan_api" not in _keys(svc, _self_subject(api=0))

    def test_dev_0_blendet_dependency_aus(self, repo) -> None:
        svc = WorkflowService(repo)
        assert "self_scan_dependency" not in _keys(svc, _self_subject(dev=0))

    def test_flag_1_zeigt_schritt(self, repo) -> None:
        svc = WorkflowService(repo)
        assert "self_scan_cert" in _keys(svc, _self_subject(website=1))

    def test_gating_deaktiviert_zeigt_alle(self, repo) -> None:
        svc = WorkflowService(repo, gating_enabled=False)
        # website=0 wuerde cert normal ausblenden — mit gating_enabled=False nicht.
        assert "self_scan_cert" in _keys(svc, _self_subject(website=0))
        assert len(svc.steps_for_subject(_self_subject(website=0))) == 14

    def test_kunde_hat_6_und_kein_gating(self, repo) -> None:
        svc = WorkflowService(repo)
        steps = svc.steps_for_subject(_kunde())
        assert len(steps) == 6
        assert all(s.applies_to == "kunde" for s in steps)


class TestView:
    def test_leere_view_alles_offen(self, repo) -> None:
        svc = WorkflowService(repo)
        view = svc.get_view(_self_subject())
        assert view.is_self is True
        assert view.subject_name == "Mein System"
        assert view.summary.percent_done == 0
        assert all(sv.status == WorkflowStepStatus.OFFEN for sv in view.steps)

    def test_status_wird_gemerged(self, repo) -> None:
        svc = WorkflowService(repo)
        svc.set_status("self-1", "self_scan_system", "erledigt")
        view = svc.get_view(_self_subject())
        done = {sv.step.step_key: sv.status for sv in view.steps}
        assert done["self_scan_system"] == WorkflowStepStatus.ERLEDIGT
        assert view.summary.done == 1

    def test_notiz_wird_gemerged(self, repo) -> None:
        svc = WorkflowService(repo)
        svc.set_note("self-1", "self_scan_system", "erledigt am Montag")
        view = svc.get_view(_self_subject())
        note = {sv.step.step_key: sv.note for sv in view.steps}
        assert note["self_scan_system"] == "erledigt am Montag"

    def test_reset_setzt_zurueck(self, repo) -> None:
        svc = WorkflowService(repo)
        svc.set_status("self-1", "self_scan_system", "erledigt")
        assert svc.reset("self-1") == 1
        view = svc.get_view(_self_subject())
        assert view.summary.done == 0

    def test_subjekt_isolation(self, repo) -> None:
        svc = WorkflowService(repo)
        svc.set_status("self-1", "self_scan_system", "erledigt")
        # Kunde hat den Schritt gar nicht — eigener Fortschritt, eigene subject_id.
        assert svc.get_view(_kunde()).summary.done == 0
