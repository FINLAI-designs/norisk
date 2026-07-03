"""
tests/test_mainpage — Tests für das Mainpage-Dashboard (Etappe 2).

Prüft Application-Services und ChangelogParser auf korrekte Funktionalität.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import textwrap

import pytest

from tools.mainpage.application.changelog_parser import ChangelogParser
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
def journal(repo):
    return JournalService(repo=repo)


@pytest.fixture()
def tasks(repo, journal):
    return TaskService(repo=repo, journal=journal)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChangelogParserLeer:
    """Changelog-Parser: Datei nicht vorhanden."""

    def test_changelog_parser_leer(self, tmp_path):
        """Parser gibt Platzhalter zurück wenn CHANGELOG.md fehlt."""
        parser = ChangelogParser()
        parser.CHANGELOG_PATH = tmp_path / "CHANGELOG.md"  # existiert nicht

        result = parser.parse()

        assert len(result) == 1
        assert result[0].version == "1.0.0"
        assert "FINLAI gestartet!" in result[0].added


class TestChangelogParserMitInhalt:
    """Changelog-Parser: Datei mit Inhalt."""

    def test_changelog_parser_mit_inhalt(self, tmp_path):
        """Parser liest Versionen, Sektionen und Einträge korrekt."""
        content = textwrap.dedent("""\
            # Changelog

            ## [1.2.0] — 2026-03-29
            ### Hinzugefügt
            - Feature A
            - Feature B
            ### Geändert
            - Änderung X

            ## [1.1.0] — 2026-02-15
            ### Hinzugefügt
            - Feature Alt
            ### Sicherheit
            - Patch Y

            ## [1.0.0] — 2026-01-01
            ### Hinzugefügt
            - Erster Start
        """)
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(content, encoding="utf-8")

        parser = ChangelogParser()
        parser.CHANGELOG_PATH = changelog

        result = parser.parse(max_versions=2)

        assert len(result) == 2
        assert result[0].version == "1.2.0"
        assert result[0].date == "2026-03-29"
        assert "Feature A" in result[0].added
        assert "Feature B" in result[0].added
        assert "Änderung X" in result[0].changed

        assert result[1].version == "1.1.0"
        assert "Patch Y" in result[1].security


class TestTaskErstellenUndAbschliessen:
    """TaskService: Task erstellen und abschließen."""

    def test_task_erstellen_und_abschliessen(self, tasks, repo):
        """complete_task setzt done-Status und legt Journal-Eintrag an."""
        task = tasks.create_task(
            title="Jahresabschluss erstellen",
            category="klient",
            klient="Muster GmbH",
            priority="high",
        )
        assert task.status == "open"
        assert not task.done_at

        tasks.move_to_in_progress(task.id)
        updated = tasks.get_task(task.id)
        assert updated is not None
        assert updated.status == "in_progress"

        tasks.complete_task(task.id)
        done = tasks.get_task(task.id)
        assert done is not None
        assert done.status == "done"
        assert done.done_at  # muss gesetzt sein

        # Journal-Eintrag task_done automatisch angelegt
        entries = repo.load_today()
        task_done = [e for e in entries if e.entry_type == "task_done"]
        assert len(task_done) == 1
        assert task_done[0].task_id == task.id


class TestCreateCriticalTask:
    """TaskService.create_critical_task."""

    def test_setzt_priority_high(self, tasks):
        """create_critical_task legt eine kritische Auto-Task an."""
        task = tasks.create_critical_task(
            title="Patch-Monitor einrichten",
            source_tool="patch_monitor",
            dedup_key="patch_monitor:winget_module_onboarding",
        )
        assert task.priority == "high"
        assert task.source == "auto"
        assert task.category == "tool"
        assert task.source_tool == "patch_monitor"

    def test_dedup_key_idempotent(self, tasks, repo):
        """Zweiter Aufruf mit gleichem dedup_key erzeugt kein Duplikat."""
        first = tasks.create_critical_task(
            title="Patch-Monitor einrichten",
            source_tool="patch_monitor",
            dedup_key="patch_monitor:winget_module_onboarding",
        )
        second = tasks.create_critical_task(
            title="Patch-Monitor einrichten (erneut)",
            source_tool="patch_monitor",
            dedup_key="patch_monitor:winget_module_onboarding",
        )
        assert second.id == first.id
        assert len(repo.load_tasks(status="open")) == 1

    def test_create_auto_task_priority_durchgereicht(self, tasks):
        """create_auto_task reicht den priority-Parameter durch."""
        task = tasks.create_auto_task(
            title="Kritischer Hinweis",
            tool_name="patch_monitor",
            priority="high",
        )
        assert task.priority == "high"


class TestTaskStatusUebergaengeT352:
    """TaskService: dismiss/reopen/update/delete."""

    def test_dismiss_setzt_status_und_begruendung(self, tasks, monkeypatch):
        """dismiss_task setzt dismissed + Begründung; Task verlässt das Board."""
        import core.audit_log as _audit

        monkeypatch.setattr(
            _audit.AuditLogger, "log_action", lambda *a, **k: None
        )
        task = tasks.create_task(title="Abzulehnende Aufgabe")
        tasks.dismiss_task(task.id, reason="betrifft uns nicht")

        dismissed = tasks.get_task(task.id)
        assert dismissed is not None
        assert dismissed.status == "dismissed"
        assert dismissed.dismissed_reason == "betrifft uns nicht"

        board = tasks.get_board_data()
        all_ids = [
            t.id
            for col in ("open", "in_progress", "done_today")
            for t in board[col]
        ]
        assert task.id not in all_ids

    def test_reopen_von_done_leert_done_at(self, tasks):
        """reopen_task: done → open, done_at wird geleert."""
        task = tasks.create_task(title="Wieder zu öffnen")
        tasks.complete_task(task.id)
        tasks.reopen_task(task.id)

        reopened = tasks.get_task(task.id)
        assert reopened is not None
        assert reopened.status == "open"
        assert reopened.done_at == ""

    def test_reopen_von_dismissed_leert_begruendung(self, tasks, monkeypatch):
        """reopen_task: dismissed → open, dismissed_reason wird geleert."""
        import core.audit_log as _audit

        monkeypatch.setattr(
            _audit.AuditLogger, "log_action", lambda *a, **k: None
        )
        task = tasks.create_task(title="Zurückgeholte Aufgabe")
        tasks.dismiss_task(task.id, reason="versehentlich")
        tasks.reopen_task(task.id)

        reopened = tasks.get_task(task.id)
        assert reopened is not None
        assert reopened.status == "open"
        assert reopened.dismissed_reason == ""

    def test_move_to_in_progress_leert_done_at(self, tasks):
        """: done → in_progress nimmt den done_at-Stempel mit zurück."""
        task = tasks.create_task(title="Zurück in Arbeit")
        tasks.complete_task(task.id)
        tasks.move_to_in_progress(task.id)

        moved = tasks.get_task(task.id)
        assert moved is not None
        assert moved.status == "in_progress"
        assert moved.done_at == ""

    def test_update_task_persistiert_felder(self, tasks):
        """update_task speichert geänderte Felder und bumpt updated_at."""
        task = tasks.create_task(title="Alter Titel")
        old_updated = task.updated_at
        task.title = "Neuer Titel"
        task.description = "Neue Beschreibung"
        tasks.update_task(task)

        loaded = tasks.get_task(task.id)
        assert loaded is not None
        assert loaded.title == "Neuer Titel"
        assert loaded.description == "Neue Beschreibung"
        assert loaded.updated_at >= old_updated

    def test_delete_task_entfernt_dauerhaft(self, tasks):
        """delete_task löscht die Aufgabe aus der DB."""
        task = tasks.create_task(title="Wegwerf-Aufgabe")
        tasks.delete_task(task.id)
        assert tasks.get_task(task.id) is None

    def test_dedup_auf_dismissed_liefert_bestand(self, tasks, monkeypatch):
        """Eine abgelehnte KI-Todo darf NICHT neu erzeugt werden (Dedup)."""
        import core.audit_log as _audit

        monkeypatch.setattr(
            _audit.AuditLogger, "log_action", lambda *a, **k: None
        )
        first = tasks.create_auto_task(
            title="KI-Vorschlag",
            tool_name="patch_monitor",
            dedup_key="patch|update|wireshark",
        )
        tasks.dismiss_task(first.id, reason="nicht relevant")

        second = tasks.create_auto_task(
            title="KI-Vorschlag (erneut)",
            tool_name="patch_monitor",
            dedup_key="patch|update|wireshark",
        )
        assert second.id == first.id
        assert second.status == "dismissed"
        assert tasks.get_board_data()["open"] == []

    def test_complete_nach_dismiss_leert_begruendung(self, tasks, monkeypatch):
        """Feld-Hygiene: done-Tasks tragen keine dismissed_reason mit."""
        import core.audit_log as _audit

        monkeypatch.setattr(
            _audit.AuditLogger, "log_action", lambda *a, **k: None
        )
        task = tasks.create_task(title="Hygiene-Check")
        tasks.dismiss_task(task.id, reason="erst abgelehnt")
        tasks.complete_task(task.id)

        done = tasks.get_task(task.id)
        assert done is not None
        assert done.status == "done"
        assert done.dismissed_reason == ""
        assert done.done_at

    def test_status_dismissed_validiert(self):
        """Task akzeptiert 'dismissed'; unbekannte Status werfen weiter."""
        from core.exceptions import ValidationError
        from tools.mainpage.domain.models import Task

        task = Task(id="t1", title="x", status="dismissed")
        assert task.status == "dismissed"

        with pytest.raises(ValidationError):
            Task(id="t2", title="x", status="erledigt")


class TestTaskHistorieT353:
    """Repository/Service: Aufgabenlog-Historie + done_note-Migration."""

    def test_task_log_sortierung_und_limit(self, tasks, monkeypatch):
        """Historie: done + dismissed, neueste zuerst, Limit greift."""
        import core.audit_log as _audit

        monkeypatch.setattr(
            _audit.AuditLogger, "log_action", lambda *a, **k: None
        )
        t1 = tasks.create_task(title="Zuerst erledigt")
        t2 = tasks.create_task(title="Danach abgelehnt")
        t3 = tasks.create_task(title="Bleibt offen")
        tasks.complete_task(t1.id)
        tasks.dismiss_task(t2.id, reason="nicht relevant")

        log = tasks.get_task_log()
        log_ids = [t.id for t in log]
        assert t1.id in log_ids
        assert t2.id in log_ids
        assert t3.id not in log_ids
        # Abgelehnt (updated_at neuer) steht vor dem früher Erledigten.
        assert log_ids.index(t2.id) < log_ids.index(t1.id)

        assert len(tasks.get_task_log(limit=1)) == 1

    def test_done_note_roundtrip(self, tasks):
        """done_note überlebt Speichern + Laden (Index-18-Migration)."""
        task = tasks.create_auto_task(
            title="Auto-Task", tool_name="patch_monitor", dedup_key="k1"
        )
        tasks.auto_complete_task(task.id, note="Update installiert")

        loaded = tasks.get_task(task.id)
        assert loaded is not None
        assert loaded.done_note == "Update installiert"
        assert loaded.status == "done"

    def test_migration_idempotent(self, repo):
        """Zweiter Migrationslauf auf derselben DB crasht nicht (Guards)."""
        repo._migrate()  # noqa: SLF001 — bewusst erneut auf derselben DB
        assert repo.load_tasks() == []

    def test_migration_auf_alt_schema_ohne_neue_spalten(self, monkeypatch):
        """R24: Bestands-DB mit Ur-Schema (12 Spalten) wird sauber migriert.

        Simuliert eine Pre-S2a-/Pre--Kunden-DB: Alt-DDL OHNE die
        Migrations-Spalten, eine Bestandszeile — danach normale
        Repo-Initialisierung (CREATE IF NOT EXISTS = No-op + ALTERs).
        """
        import sqlite3
        from contextlib import contextmanager

        import core.database.encrypted_db as edb

        shared = sqlite3.connect(":memory:")
        shared.row_factory = sqlite3.Row
        shared.executescript(
            """
            CREATE TABLE tasks (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                description TEXT DEFAULT '',
                status      TEXT DEFAULT 'open',
                category    TEXT DEFAULT 'allgemein',
                source      TEXT DEFAULT 'manual',
                source_tool TEXT DEFAULT '',
                klient      TEXT DEFAULT '',
                priority    TEXT DEFAULT 'normal',
                created_at  TEXT,
                updated_at  TEXT,
                done_at     TEXT
            );
            """
        )
        shared.execute(
            "INSERT INTO tasks (id, title) VALUES ('alt-1', 'Bestand')"
        )
        shared.commit()

        def _patched_init(self, name: str) -> None:
            self._name = name
            self._conn = shared

        @contextmanager
        def _patched_connection(self):
            yield self._conn

        def _patched_init_schema(self, schema: str) -> None:
            self._conn.executescript(schema)
            self._conn.commit()

        monkeypatch.setattr(edb.EncryptedDatabase, "__init__", _patched_init)
        monkeypatch.setattr(
            edb.EncryptedDatabase, "connection", _patched_connection
        )
        monkeypatch.setattr(
            edb.EncryptedDatabase, "init_schema", _patched_init_schema
        )

        migrated = MainpageRepository()
        loaded = migrated.load_tasks()
        assert [t.id for t in loaded] == ["alt-1"]
        assert loaded[0].done_note == ""
        assert loaded[0].dedup_key == ""

        # Roundtrip: neue Spalte ist nach der Migration beschreibbar.
        loaded[0].done_note = "Automatisch erledigt"
        migrated.save_task(loaded[0])
        assert migrated.load_task("alt-1").done_note == "Automatisch erledigt"


class TestJournalAutoEintrag:
    """JournalService: automatische Einträge."""

    def test_journal_auto_eintrag(self, journal):
        """add_tool_used und add_from_audit_log legen korrekte Einträge an."""
        journal.add_tool_used("xml_reader", details="5 Schemata importiert")
        journal.add_from_audit_log(
            action="Export abgeschlossen",
            tool="maps",
            details="12 Zeilen exportiert",
        )

        summary = journal.get_today_summary()

        assert summary["total"] == 2
        tool_entries = summary["tools_used"]
        assert len(tool_entries) == 1
        assert tool_entries[0].tool_name == "xml_reader"
        assert tool_entries[0].content == "5 Schemata importiert"

        auto_entries = [e for e in summary["entries"] if e.entry_type == "auto"]
        assert len(auto_entries) == 1
        assert auto_entries[0].title == "Export abgeschlossen"
        assert auto_entries[0].tool_name == "maps"


class TestBoardDatenVollstaendig:
    """TaskService: get_board_data gibt vollständige Struktur zurück."""

    def test_board_daten_vollstaendig(self, tasks):
        """Board-Daten enthalten open, in_progress und done_today."""
        t_open = tasks.create_task(title="Offene Aufgabe")
        t_progress = tasks.create_task(title="In Arbeit")
        t_done = tasks.create_task(title="Erledigte Aufgabe")

        tasks.move_to_in_progress(t_progress.id)
        tasks.complete_task(t_done.id)

        board = tasks.get_board_data()

        assert "open" in board
        assert "in_progress" in board
        assert "done_today" in board

        open_ids = [t.id for t in board["open"]]
        assert t_open.id in open_ids

        progress_ids = [t.id for t in board["in_progress"]]
        assert t_progress.id in progress_ids

        done_ids = [t.id for t in board["done_today"]]
        assert t_done.id in done_ids


class TestActivityFeedDateLabel:
    """ — Datum-Formatierung im Activity-Feed."""

    def _format(self, ts_iso: str, today_iso: str) -> str:
        """Test-Helper: ruft _format_date_label mit fixiertem ``today``."""
        from datetime import datetime  # noqa: PLC0415

        from tools.mainpage.gui.activity_widget import (
            _format_date_label,  # noqa: PLC0415
        )

        dt = datetime.fromisoformat(ts_iso)
        today = datetime.fromisoformat(today_iso)
        return _format_date_label(dt, today=today)

    def test_heute(self) -> None:
        assert self._format("2026-05-07T14:23:45", "2026-05-07T20:00:00") == "Heute"

    def test_heute_in_der_nacht(self) -> None:
        """Eintrag um 04:41, jetzt 22:00 — selber Tag bleibt 'Heute'."""
        assert self._format("2026-05-07T04:41:00", "2026-05-07T22:00:00") == "Heute"

    def test_gestern(self) -> None:
        assert self._format("2026-05-06T20:51:00", "2026-05-07T08:00:00") == "Gestern"

    def test_aelter_als_gestern(self) -> None:
        """3 Tage zurueck → ``TT.MM.`` (deutsche Notation, mit Punkt am Ende)."""
        assert self._format("2026-05-04T12:00:00", "2026-05-07T08:00:00") == "04.05."

    def test_jahreswechsel(self) -> None:
        """31.12. vs. 01.01. → ``Gestern``, Vorjahr-Tag → ``TT.MM.``."""
        assert self._format("2025-12-31T23:59:00", "2026-01-01T08:00:00") == "Gestern"
        assert self._format("2025-12-30T23:59:00", "2026-01-01T08:00:00") == "30.12."
