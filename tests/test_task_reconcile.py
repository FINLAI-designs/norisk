"""Tests für die KI-Todo-Reconciliation.

Voll-Sync ``KiTodoService.sync_findings``: offene Auto-Tasks, deren
Quell-Finding verschwunden ist, werden automatisch erledigt (done_note +
Journal); Tasks mit aktivem Finding bekommen frische Titel; dismissed
Tasks sind dreifach geschützt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from core.rules.models import ClassifierHint, Rule, RuleMatch
from core.rules.rule_engine import RuleEngine
from core.storytelling.narrative_builder import build_story
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.ki_todo_service import (
    _NOTE_RESOLVED,
    _NOTE_SUPERSEDED,
    KiTodoService,
    compute_dedup_key,
)
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository

# ---------------------------------------------------------------------------
# Fixtures — In-Memory-Repo (Muster tests/test_mainpage.py)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _kein_audit_file(monkeypatch):
    """AuditLogger schreibt im Test keine Dateien."""
    import core.audit_log as _audit

    monkeypatch.setattr(_audit.AuditLogger, "log_action", lambda *a, **k: None)


@pytest.fixture()
def repo(monkeypatch):
    """Isoliertes In-Memory-Repository (kein SQLCipher)."""
    import sqlite3
    from contextlib import contextmanager

    import core.database.encrypted_db as edb

    def _patched_init(self, name: str) -> None:
        self._name = name
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row

    @contextmanager
    def _patched_connection(self):
        yield self._conn

    def _patched_init_schema(self, schema: str) -> None:
        self._conn.executescript(schema)
        self._conn.commit()

    monkeypatch.setattr(edb.EncryptedDatabase, "__init__", _patched_init)
    monkeypatch.setattr(edb.EncryptedDatabase, "connection", _patched_connection)
    monkeypatch.setattr(edb.EncryptedDatabase, "init_schema", _patched_init_schema)

    return MainpageRepository()


@pytest.fixture()
def tasks(repo) -> TaskService:
    return TaskService(repo=repo, journal=JournalService(repo=repo))


@pytest.fixture()
def service(tasks) -> KiTodoService:
    """KiTodoService mit minimaler Cert-Regel (Muster test_ki_todo_service)."""
    rule = Rule(
        id="cert_expiring",
        match=RuleMatch(
            tool="cert_monitor",
            finding_type="cert_expiring",
            min_severity=Severity.LOW,
        ),
        classifier_hint=ClassifierHint(asset_count=1, action_keywords=["renew"]),
    )
    return KiTodoService(tasks, RuleEngine([rule]))


def _finding(
    evidence_id: str = "cert-1",
    *,
    finding_type: str = "cert_expiring",
    subject: str = "example.com",
    days_left: int = 5,
) -> FindingInput:
    return FindingInput(
        tool="cert_monitor",
        finding_type=finding_type,
        severity=Severity.HIGH,
        subject=subject,
        evidence_id=evidence_id,
        details={"days_left": days_left, "expires_at": "2026-05-04"},
    )


# ---------------------------------------------------------------------------
# Perf (Tier 3): Index fuer load_tasks_by_source_tool
# ---------------------------------------------------------------------------


def test_index_tasks_source_tool_exists(repo):
    """Der additive Index idx_tasks_source_tool wird beim Schema-Init angelegt
    (deckt die Reconciliation-Query source_tool + status -> Index-Seek)."""
    with repo._db.connection() as conn:  # noqa: SLF001
        names = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
    assert "idx_tasks_source_tool" in names


# ---------------------------------------------------------------------------
# Auto-Erledigung
# ---------------------------------------------------------------------------


def test_finding_weg_erledigt_task_mit_note_und_journal(service, tasks, repo):
    """Verschwundenes Finding → Task done + done_note + Journal-Eintrag."""
    created = service.sync_findings("cert_monitor", [_finding()])
    assert len(created) == 1
    assert created[0].status == "open"

    service.sync_findings("cert_monitor", [])

    task = tasks.get_task(created[0].id)
    assert task is not None
    assert task.status == "done"
    assert task.done_note == _NOTE_RESOLVED
    assert task.done_at

    auto_entries = [
        e for e in repo.load_today() if e.entry_type == "auto"
    ]
    assert len(auto_entries) == 1
    assert auto_entries[0].task_id == task.id
    assert auto_entries[0].title.startswith("Automatisch erledigt:")


def test_finding_noch_da_task_bleibt_offen(service, tasks):
    """Aktives Finding → Task bleibt unverändert offen."""
    created = service.sync_findings("cert_monitor", [_finding()])
    service.sync_findings("cert_monitor", [_finding()])

    task = tasks.get_task(created[0].id)
    assert task is not None
    assert task.status == "open"
    assert task.done_note == ""


def test_leere_liste_erledigt_alle_offenen_auto_tasks(service, tasks):
    """Kernfall: 'alles installiert' → ALLE offenen Auto-Tasks des Tools done."""
    service.sync_findings(
        "cert_monitor", [_finding("cert-1"), _finding("cert-2")]
    )
    tasks_open = tasks.get_active_auto_tasks("cert_monitor")
    assert len(tasks_open) == 2

    service.sync_findings("cert_monitor", [])

    assert tasks.get_active_auto_tasks("cert_monitor") == []
    log = tasks.get_task_log()
    assert len(log) == 2
    assert all(t.done_note == _NOTE_RESOLVED for t in log)


def test_in_progress_task_wird_auch_erledigt(service, tasks):
    """Auch Tasks in Arbeit werden geschlossen, wenn das Finding weg ist."""
    created = service.sync_findings("cert_monitor", [_finding()])
    tasks.move_to_in_progress(created[0].id)

    service.sync_findings("cert_monitor", [])

    task = tasks.get_task(created[0].id)
    assert task is not None
    assert task.status == "done"


# ---------------------------------------------------------------------------
# Dismissed-Schutz
# ---------------------------------------------------------------------------


def test_dismissed_task_wird_nicht_auto_erledigt(service, tasks):
    """Abgelehnte Task bleibt dismissed — auch wenn das Finding weg ist."""
    created = service.sync_findings("cert_monitor", [_finding()])
    tasks.dismiss_task(created[0].id, reason="betrifft uns nicht")

    service.sync_findings("cert_monitor", [])

    task = tasks.get_task(created[0].id)
    assert task is not None
    assert task.status == "dismissed"
    assert task.done_at == ""
    assert task.done_note == ""


def test_dismissed_task_wird_nicht_neu_erzeugt(service, tasks):
    """Dedup-Schutz: identisches Finding erzeugt keine zweite Task."""
    created = service.sync_findings("cert_monitor", [_finding()])
    tasks.dismiss_task(created[0].id)

    results = service.sync_findings("cert_monitor", [_finding()])

    # Dedup-Hit liefert die dismissed Bestand-Task, keine neue.
    assert len(results) == 1
    assert results[0].id == created[0].id
    assert tasks.get_board_data()["open"] == []


def test_auto_complete_auf_done_und_dismissed_ist_noop(service, tasks):
    """Doppeltes Netz: auto_complete_task fasst done/dismissed nie an."""
    created = service.sync_findings("cert_monitor", [_finding()])
    task_id = created[0].id

    tasks.dismiss_task(task_id, reason="abgelehnt")
    tasks.auto_complete_task(task_id, note="darf nicht greifen")
    task = tasks.get_task(task_id)
    assert task.status == "dismissed"
    assert task.done_note == ""

    tasks.reopen_task(task_id)
    tasks.complete_task(task_id)
    tasks.auto_complete_task(task_id, note="darf nicht greifen")
    task = tasks.get_task(task_id)
    assert task.done_note == ""


# ---------------------------------------------------------------------------
# Titel-Refresh (Stale-Version-Fix)
# ---------------------------------------------------------------------------


def test_geaendertes_finding_frischt_titel_und_beschreibung_auf(
    service, tasks
):
    """Gleicher dedup_key, neue Details → Story wird neu gerendert."""
    created = service.sync_findings("cert_monitor", [_finding(days_left=5)])
    old_title = created[0].title

    updated_finding = _finding(days_left=2)
    service.sync_findings("cert_monitor", [updated_finding])

    task = tasks.get_task(created[0].id)
    expected = build_story(updated_finding)
    assert task.title == expected.headline
    assert task.title != old_title
    assert expected.action in task.description


def test_unveraendertes_finding_speichert_nicht(service, tasks):
    """Kein unnötiges updated_at-Bumpen bei identischer Story."""
    created = service.sync_findings("cert_monitor", [_finding()])
    before = tasks.get_task(created[0].id).updated_at

    service.sync_findings("cert_monitor", [_finding()])

    after = tasks.get_task(created[0].id).updated_at
    assert after == before


# ---------------------------------------------------------------------------
# Supersede + Abgrenzung
# ---------------------------------------------------------------------------


def test_supersede_gleiches_subjekt_neuer_finding_type(service, tasks):
    """Recommendation-Wechsel: evidence_id aktiv, Key weg → SUPERSEDED-Note."""
    created = service.sync_findings("cert_monitor", [_finding("cert-1")])

    # Gleiches Subjekt, neuer finding_type → neuer dedup_key.
    service.sync_findings(
        "cert_monitor", [_finding("cert-1", finding_type="cert_expired")]
    )

    task = tasks.get_task(created[0].id)
    assert task.status == "done"
    assert task.done_note == _NOTE_SUPERSEDED


def test_fremde_und_manuelle_tasks_bleiben_unberuehrt(service, tasks):
    """Reconciliation fasst nur Auto-Tasks des eigenen Tools an."""
    manual = tasks.create_task(title="Manuelle Aufgabe")
    foreign = tasks.create_auto_task(
        title="Fremdes Tool",
        tool_name="api_security",
        dedup_key=compute_dedup_key("api_security", "x", "y"),
    )
    keyless = tasks.create_auto_task(
        title="Alt-Bestand ohne Dedup", tool_name="cert_monitor"
    )

    service.sync_findings("cert_monitor", [])

    assert tasks.get_task(manual.id).status == "open"
    assert tasks.get_task(foreign.id).status == "open"
    assert tasks.get_task(keyless.id).status == "open"


def test_task_ohne_evidence_refs_bleibt_unberuehrt(service, tasks):
    """Nicht Finding-gestützte Auto-Tasks Scan-Reminder) sind tabu.

    Der Reminder hat einen dedup_key, aber KEINE evidence_refs — sein
    "Finding" kann nie in der Scan-Liste auftauchen, eine Auto-Erledigung
    mit "Update installiert" wäre irreführend.
    """
    reminder = tasks.create_critical_task(
        title="Ersten Patch-Scan starten",
        source_tool="cert_monitor",
        dedup_key="cert_monitor:scan_reminder",
    )

    service.sync_findings("cert_monitor", [])

    task = tasks.get_task(reminder.id)
    assert task.status == "open"
    assert task.done_note == ""


# ---------------------------------------------------------------------------
# Wiederkehrende Findings (Review-P1: versions-loser dedup_key)
# ---------------------------------------------------------------------------


def test_finding_kommt_wieder_task_wird_reopened(service, tasks):
    """Update installiert → Monate später neues Update derselben App.

    Der versions-lose dedup_key würde die Folge-Task sonst dauerhaft
    blockieren (Dedup-Hit liefert die done-Task, legt nichts an).
    """
    created = service.sync_findings("cert_monitor", [_finding(days_left=5)])
    task_id = created[0].id

    # Update installiert: Finding weg → auto-erledigt.
    service.sync_findings("cert_monitor", [])
    assert tasks.get_task(task_id).status == "done"

    # Neues Update: Finding (gleicher Key) wieder aktiv → reopen + Refresh.
    neues_finding = _finding(days_left=3)
    service.sync_findings("cert_monitor", [neues_finding])

    task = tasks.get_task(task_id)
    assert task.status == "open"
    assert task.done_note == ""
    assert task.title == build_story(neues_finding).headline


def test_manuell_erledigte_task_mit_aktivem_finding_wird_reopened(
    service, tasks
):
    """Auch manuell Erledigtes kommt zurück, solange das Finding aktiv ist.

    Das Board soll die Realität zeigen; dauerhaftes Ausblenden ist
    "Aufgabe ablehnen" (dismissed bleibt geschützt).
    """
    created = service.sync_findings("cert_monitor", [_finding()])
    tasks.complete_task(created[0].id)

    service.sync_findings("cert_monitor", [_finding()])

    assert tasks.get_task(created[0].id).status == "open"


def test_dismissed_wird_bei_aktivem_finding_nicht_reopened(service, tasks):
    """Reopen-Pfad respektiert die Ablehnung (nur done-Kandidaten)."""
    created = service.sync_findings("cert_monitor", [_finding()])
    tasks.dismiss_task(created[0].id, reason="bewusst ignoriert")

    service.sync_findings("cert_monitor", [_finding()])

    assert tasks.get_task(created[0].id).status == "dismissed"


def test_reconcile_ignoriert_fremde_findings_in_der_liste(service, tasks):
    """Defensiv: Findings anderer Tools verfälschen den Abgleich nicht."""
    created = service.sync_findings("cert_monitor", [_finding()])

    fremd = FindingInput(
        tool="api_security",
        finding_type="missing_header",
        severity=Severity.HIGH,
        subject="example.com",
        evidence_id="cert-1",  # gleiche evidence_id wie die Cert-Task!
        details={},
    )
    # Eigenes Finding weg, nur das fremde in der Liste: Die Task muss
    # RESOLVED schließen — das fremde Finding darf weder als "aktiv"
    # noch als Supersede-Beleg zählen.
    service.sync_findings("cert_monitor", [fremd])

    task = tasks.get_task(created[0].id)
    assert task.status == "done"
    assert task.done_note == _NOTE_RESOLVED


# ---------------------------------------------------------------------------
# done_note-Hygiene (Review-P2)
# ---------------------------------------------------------------------------


def test_reopen_und_manuelles_erledigen_leert_done_note(service, tasks):
    """Auto-erledigt → reopen → manuell erledigt: Log zeigt 'Erledigt'."""
    created = service.sync_findings("cert_monitor", [_finding()])
    service.sync_findings("cert_monitor", [])
    task_id = created[0].id
    assert tasks.get_task(task_id).done_note == _NOTE_RESOLVED

    tasks.reopen_task(task_id)
    assert tasks.get_task(task_id).done_note == ""

    tasks.complete_task(task_id)
    done = tasks.get_task(task_id)
    assert done.status == "done"
    assert done.done_note == ""  # manuell erledigt, keine Auto-Notiz


def test_dismiss_nach_auto_erledigt_leert_done_note(service, tasks):
    """Auto-erledigt → reopen → abgelehnt: Notiz-Spalte zeigt Begründung."""
    created = service.sync_findings("cert_monitor", [_finding()])
    service.sync_findings("cert_monitor", [])
    task_id = created[0].id

    tasks.reopen_task(task_id)
    tasks.dismiss_task(task_id, reason="manuell verworfen")

    task = tasks.get_task(task_id)
    assert task.status == "dismissed"
    assert task.done_note == ""
    assert task.dismissed_reason == "manuell verworfen"
