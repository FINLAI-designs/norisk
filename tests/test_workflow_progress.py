"""test_workflow_progress — Domain + Persistenz des Cockpit-Workflow-Tabs.

Deckt Phase 1 ab (kein GUI, kein SQLCipher):
    * Domain: Checklisten-Definition (self=14, kunde=6), ``compute_summary``
      (Prozent-Semantik: nicht_relevant raus, uebersprungen im Nenner),
      ``normalize_status``.
    * Data: ``WorkflowProgressRepository`` gegen einen In-Memory-SQLite-Stub —
      UPSERT, Notiz-Erhalt, Subjekt-Isolation, Reset.
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.norisk_dashboard.data.workflow_progress_repository import (
    WorkflowProgressRepository,
)
from tools.norisk_dashboard.domain.exceptions import WorkflowDataError
from tools.norisk_dashboard.domain.workflow_definition import (
    WORKFLOW_STEPS,
    step_by_key,
    steps_for_kind,
)
from tools.norisk_dashboard.domain.workflow_models import (
    WorkflowStepDef,
    WorkflowStepStatus,
    compute_summary,
    normalize_status,
)

# ===========================================================================
# Domain — Definition
# ===========================================================================


class TestWorkflowDefinition:
    def test_self_hat_14_schritte(self) -> None:
        assert len(steps_for_kind("self")) == 14

    def test_kunde_hat_6_schritte(self) -> None:
        assert len(steps_for_kind("kunde")) == 6

    def test_self_ist_nach_order_sortiert(self) -> None:
        steps = steps_for_kind("self")
        assert [s.order for s in steps] == sorted(s.order for s in steps)

    def test_kunde_kein_technischer_scan(self) -> None:
        # Kundensysteme werden nicht technisch gescannt (SubjectKind.KUNDE-Vertrag).
        scan_navs = {
            "system_scanner",
            "network_scanner",
            "cert_monitor",
            "api_security",
            "dependency_auditor",
            "file_scanner",
            "password_checker",
            "security_scoring",
        }
        kunde_navs = {s.nav_key for s in steps_for_kind("kunde")}
        assert not (kunde_navs & scan_navs)

    def test_score_kommt_nach_allen_scans(self) -> None:
        # Der Score-Schritt muss NACH den Scan-Schritten liegen (frische Daten).
        by_key = {s.step_key: s.order for s in WORKFLOW_STEPS}
        score = by_key["self_compute_score"]
        for scan in ("self_scan_system", "self_scan_network", "self_scan_files"):
            assert by_key[scan] < score

    def test_step_by_key(self) -> None:
        assert step_by_key("self_scan_system") is not None
        assert step_by_key("gibt_es_nicht") is None

    def test_step_keys_eindeutig(self) -> None:
        keys = [s.step_key for s in WORKFLOW_STEPS]
        assert len(keys) == len(set(keys))


# ===========================================================================
# Domain — normalize_status + compute_summary
# ===========================================================================


class TestStatusHelpers:
    def test_normalize_akzeptiert_enum_und_string(self) -> None:
        assert normalize_status("erledigt") is WorkflowStepStatus.ERLEDIGT
        assert normalize_status(WorkflowStepStatus.OFFEN) is WorkflowStepStatus.OFFEN

    def test_normalize_ungueltig_wirft(self) -> None:
        with pytest.raises(ValueError):
            normalize_status("kaputt")


def _steps(*keys: str) -> list[WorkflowStepDef]:
    return [
        WorkflowStepDef(
            step_key=k, phase="P", titel=k, beschreibung="", nav_key="home", order=i
        )
        for i, k in enumerate(keys)
    ]


class TestComputeSummary:
    def test_alles_offen_null_prozent(self) -> None:
        s = compute_summary(_steps("a", "b"), {})
        assert s.percent_done == 0
        assert s.relevant == 2
        assert s.offen == 2

    def test_prozent_semantik(self) -> None:
        # a=erledigt, b=uebersprungen (Nenner, nicht Zaehler),
        # c=nicht_relevant (raus), d=offen.
        steps = _steps("a", "b", "c", "d")
        statuses = {
            "a": "erledigt",
            "b": "uebersprungen",
            "c": "nicht_relevant",
            "d": "offen",
        }
        s = compute_summary(steps, statuses)
        assert s.total == 4
        assert s.not_relevant == 1
        assert s.relevant == 3
        assert s.done == 1
        assert s.skipped == 1
        assert s.offen == 1
        assert s.percent_done == 33

    def test_alles_erledigt_100(self) -> None:
        s = compute_summary(_steps("a", "b"), {"a": "erledigt", "b": "erledigt"})
        assert s.percent_done == 100


# ===========================================================================
# Data — Repository (In-Memory-SQLite-Stub, kein SQLCipher)
# ===========================================================================


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


class TestWorkflowProgressRepository:
    def test_leer_liefert_leeres_dict(self, repo: WorkflowProgressRepository) -> None:
        assert repo.get_progress("subj-1") == {}

    def test_set_status_und_lesen(self, repo: WorkflowProgressRepository) -> None:
        repo.set_status("subj-1", "self_scan_system", "erledigt")
        progress = repo.get_progress("subj-1")
        assert progress["self_scan_system"].status == "erledigt"

    def test_upsert_kein_duplikat(self, repo: WorkflowProgressRepository) -> None:
        repo.set_status("subj-1", "self_scan_system", "in_arbeit")
        repo.set_status("subj-1", "self_scan_system", "erledigt")
        progress = repo.get_progress("subj-1")
        assert len(progress) == 1
        assert progress["self_scan_system"].status == "erledigt"

    def test_set_status_note_none_erhaelt_notiz(
        self, repo: WorkflowProgressRepository
    ) -> None:
        repo.set_note("subj-1", "self_scan_system", "Firewall geprüft")
        repo.set_status("subj-1", "self_scan_system", "erledigt")  # note=None
        progress = repo.get_progress("subj-1")
        assert progress["self_scan_system"].status == "erledigt"
        assert progress["self_scan_system"].note == "Firewall geprüft"

    def test_set_note_erhaelt_status(self, repo: WorkflowProgressRepository) -> None:
        repo.set_status("subj-1", "self_scan_system", "in_arbeit")
        repo.set_note("subj-1", "self_scan_system", "läuft noch")
        progress = repo.get_progress("subj-1")
        assert progress["self_scan_system"].status == "in_arbeit"
        assert progress["self_scan_system"].note == "läuft noch"

    def test_subjekt_isolation(self, repo: WorkflowProgressRepository) -> None:
        repo.set_status("subj-1", "self_scan_system", "erledigt")
        repo.set_status("subj-2", "self_scan_system", "offen")
        assert repo.get_progress("subj-1")["self_scan_system"].status == "erledigt"
        assert repo.get_progress("subj-2")["self_scan_system"].status == "offen"

    def test_reset_loescht_nur_ein_subjekt(
        self, repo: WorkflowProgressRepository
    ) -> None:
        repo.set_status("subj-1", "self_scan_system", "erledigt")
        repo.set_status("subj-1", "self_scan_network", "erledigt")
        repo.set_status("subj-2", "self_scan_system", "erledigt")
        deleted = repo.reset("subj-1")
        assert deleted == 2
        assert repo.get_progress("subj-1") == {}
        assert repo.get_progress("subj-2") != {}

    def test_ungueltiger_status_wirft(
        self, repo: WorkflowProgressRepository
    ) -> None:
        # R-Exc: die data/-Schicht uebersetzt das rohe ValueError in
        # eine tool-eigene WorkflowDataError (die weiterhin von ValueError erbt?
        # Nein — von WorkflowError; daher explizit auf WorkflowDataError pruefen).
        with pytest.raises(WorkflowDataError):
            repo.set_status("subj-1", "self_scan_system", "kaputt")
