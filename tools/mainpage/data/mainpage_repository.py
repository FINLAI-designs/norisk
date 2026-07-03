"""
mainpage_repository — SQLCipher-Repository für das Mainpage-Dashboard.

Speichert und lädt Tasks, Journal-Einträge und Tool-Nutzungs-Historie
in einer verschlüsselten SQLite-Datenbank.

Sicherheitshinweise:
    - Alle SQL-Abfragen sind parametrisiert (kein String-Join).
    - Datenbank AES-256-CBC verschlüsselt via EncryptedDatabase.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from tools.mainpage.domain.models import JournalEntry, Task

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
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

CREATE TABLE IF NOT EXISTS journal_entries (
    id         TEXT PRIMARY KEY,
    date       TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    title      TEXT NOT NULL,
    content    TEXT DEFAULT '',
    tool_name  TEXT DEFAULT '',
    task_id    TEXT DEFAULT '',
    metadata   TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS recent_tools (
    tool_name  TEXT NOT NULL,
    used_at    TEXT NOT NULL,
    app_id     TEXT NOT NULL DEFAULT 'finlai'
);

CREATE INDEX IF NOT EXISTS idx_tasks_status
    ON tasks(status);

-- Perf (Tier 3): deckt die Reconciliation-Query load_tasks_by_source_tool
-- (WHERE source_tool = ? AND status IN (...)) ab -> Index-Seek statt
-- Tabellen-Scan. Additiv/idempotent (CREATE INDEX IF NOT EXISTS), greift via
-- init_schema auch auf Bestands-DBs beim naechsten Open.
CREATE INDEX IF NOT EXISTS idx_tasks_source_tool
    ON tasks(source_tool, status);

CREATE INDEX IF NOT EXISTS idx_journal_date
    ON journal_entries(date);

CREATE INDEX IF NOT EXISTS idx_recent_tools_used_at
    ON recent_tools(used_at DESC);
"""


def _now_iso() -> str:
    """Gibt den aktuellen UTC-Zeitstempel als ISO-8601-String zurück."""
    return datetime.now(UTC).isoformat()


def _today() -> str:
    """Gibt das heutige Datum als ``YYYY-MM-DD``-String zurück."""
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _decode_evidence_refs(raw: object) -> list[dict]:
    """Parst die ``evidence_refs``-JSON-Spalte defensiv.

    Robust gegen ``NULL``, leere Strings und kaputtes JSON — in solchen
    Fällen liefert die Funktion eine leere Liste, damit ``Task``-Validierung
    nicht crashen.
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return raw  # bereits dekodiert (z. B. aus Tests)
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


class MainpageRepository:
    """Datenzugriffsschicht für das Mainpage-Dashboard.

    Alle Schreiboperationen validieren die Eingabeobjekte implizit
    über die ``__post_init__``-Methoden der Dataclasses.

    Attributes:
        _db: Verschlüsselte Datenbankverbindung.
    """

    def __init__(self) -> None:
        """Initialisiert das Repository und erstellt das Datenbankschema."""
        self._db = EncryptedDatabase("mainpage")
        self._db.init_schema(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Führt Datenbank-Migrationen durch (idempotent).

        Jede ``ALTER TABLE``-Anweisung steht in eigenem ``try``/``except`` —
        SQLite wirft ``OperationalError: duplicate column name``, wenn die
        Spalte bereits existiert. Wir fangen das ab statt zuerst per
        ``PRAGMA table_info`` zu prüfen, weil die idempotente Variante
        kürzer und für Sprint-Migrationen ausreichend robust ist.
        """
        migrations = [
            "ALTER TABLE recent_tools ADD COLUMN app_id TEXT NOT NULL DEFAULT 'finlai'",
            # Sprint S2a — neue tasks-Spalten für die KI-Todo-Regel-Engine.
            # Defaults bewusst gesetzt, damit bestehende Zeilen ohne Re-Save
            # gültig bleiben.
            "ALTER TABLE tasks ADD COLUMN urgency TEXT NOT NULL DEFAULT 'mittel'",
            "ALTER TABLE tasks ADD COLUMN snoozed_until TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN evidence_refs TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE tasks ADD COLUMN dismissed_reason TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN dedup_key TEXT NOT NULL DEFAULT ''",
            # Auto-Erledigt-Notiz. APPEND-ONLY: ``_row_to_task``
            # liest per Index (done_note = Index 18); neue Spalten immer
            # ans Listen-Ende.
            "ALTER TABLE tasks ADD COLUMN done_note TEXT NOT NULL DEFAULT ''",
        ]
        with self._db.connection() as conn:
            for stmt in migrations:
                try:
                    conn.execute(stmt)
                except Exception:  # noqa: BLE001
                    pass  # Spalte existiert bereits → ignorieren
            # Eindeutiger Index auf dedup_key (nur wo gesetzt) — verhindert
            # Race-Conditions beim parallelen Anlegen identischer KI-Todos.
            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_dedup_key"
                    " ON tasks(dedup_key) WHERE dedup_key != ''"
                )
            except Exception:  # noqa: BLE001
                pass

    # -----------------------------------------------------------------------
    # Task-Methoden
    # -----------------------------------------------------------------------

    def save_task(self, task: Task) -> None:
        """Speichert eine Aufgabe (INSERT OR REPLACE).

        Args:
            task: Zu speichernde Task-Instanz.
        """
        now = _now_iso()
        created = task.created_at or now
        updated = task.updated_at or now
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tasks
                    (id, title, description, status, category, source,
                     source_tool, klient, priority, created_at, updated_at,
                     done_at, urgency, snoozed_until, pinned, evidence_refs,
                     dismissed_reason, dedup_key, done_note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.id,
                    task.title,
                    task.description,
                    task.status,
                    task.category,
                    task.source,
                    task.source_tool,
                    task.klient,
                    task.priority,
                    created,
                    updated,
                    task.done_at,
                    task.urgency,
                    task.snoozed_until,
                    1 if task.pinned else 0,
                    json.dumps(task.evidence_refs, ensure_ascii=False),
                    task.dismissed_reason,
                    task.dedup_key,
                    task.done_note,
                ),
            )
        logger.debug("Task gespeichert: %s", task.id)

    def find_task_by_dedup_key(self, dedup_key: str) -> Task | None:
        """Findet eine Task anhand des ``dedup_key``.

        Args:
            dedup_key: Stabile Hash-Referenz auf das Quell-Finding (
                ``Task.dedup_key``). Leere Strings liefern stets ``None`` —
                ``dedup_key=""`` markiert manuelle Tasks ohne Dedup.

        Returns:
            Task oder ``None`` wenn kein Eintrag existiert.
        """
        if not dedup_key:
            return None
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE dedup_key = ?", (dedup_key,)
            ).fetchone()
        return self._row_to_task(row) if row else None

    def load_tasks(
        self,
        status: str | None = None,
        category: str | None = None,
    ) -> list[Task]:
        """Gibt Aufgaben zurück, optional nach Status und Kategorie gefiltert.

        Args:
            status: Optionaler Status-Filter (``"open"``, ``"in_progress"``,
                ``"done"``). None bedeutet alle Status.
            category: Optionaler Kategorie-Filter.

        Returns:
            Gefilterte und nach ``created_at`` sortierte Aufgabenliste.
        """
        sql = "SELECT * FROM tasks WHERE 1=1"
        params: list[str] = []
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        if category is not None:
            sql += " AND category = ?"
            params.append(category)
        sql += " ORDER BY created_at DESC"

        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_task(r) for r in rows]

    def load_task(self, task_id: str) -> Task | None:
        """Gibt eine einzelne Aufgabe anhand ihrer ID zurück.

        Args:
            task_id: UUID der gesuchten Aufgabe.

        Returns:
            Task oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._row_to_task(row) if row else None

    # ``update_status`` entfernt — Status-Übergänge laufen über die
    # TaskService-Methoden (Load→Save), weil der SQL-Pfad ``done_at`` bei
    # Nicht-done-Status stehen ließ (Stale-Stempel-Falle).

    def load_tasks_by_source_tool(
        self,
        source_tool: str,
        statuses: tuple[str, ...] = ("open", "in_progress"),
    ) -> list[Task]:
        """Gibt Auto-Tasks eines Quell-Tools in den gegebenen Status zurück.

        Kandidaten-Query der Reconciliation: nur ``source="auto"``
        — manuelle Tasks werden nie automatisch erledigt.

        Args:
            source_tool: Tool-Bezeichner (z. B. ``"patch_monitor"``).
            statuses: Status-Filter; Default sind die aktiven Status.

        Returns:
            Gefilterte Tasks, neueste zuerst.
        """
        if not statuses:
            return []  # leeres IN wäre ein SQL-Syntaxfehler
        # In die Query werden NUR "?"-Platzhalter interpoliert (einer pro
        # Status) — alle Werte laufen parametrisiert.
        placeholders = ", ".join("?" for _ in statuses)
        sql = f"SELECT * FROM tasks WHERE source = 'auto' AND source_tool = ? AND status IN ({placeholders}) ORDER BY created_at DESC"  # noqa: S608, E501 # nosec B608
        with self._db.connection() as conn:
            rows = conn.execute(sql, [source_tool, *statuses]).fetchall()
        return [self._row_to_task(r) for r in rows]

    def load_task_history(self, limit: int = 200) -> list[Task]:
        """Gibt erledigte und abgelehnte Tasks für das Aufgabenlog zurück.

        Sortiert absteigend nach ``done_at`` (falls gesetzt), sonst
        ``updated_at`` — abgelehnte Tasks haben kein ``done_at``.

        Args:
            limit: Maximale Anzahl Einträge.

        Returns:
            Historien-Tasks, neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM tasks
                WHERE status IN ('done', 'dismissed')
                ORDER BY COALESCE(NULLIF(done_at, ''), updated_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def delete_task(self, task_id: str) -> None:
        """Löscht eine Aufgabe dauerhaft.

        Args:
            task_id: UUID der zu löschenden Aufgabe.
        """
        with self._db.connection() as conn:
            conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        logger.debug("Task gelöscht: %s", task_id)

    # -----------------------------------------------------------------------
    # Journal-Methoden
    # -----------------------------------------------------------------------

    def save_entry(self, entry: JournalEntry) -> None:
        """Speichert einen Journal-Eintrag (INSERT OR REPLACE).

        Args:
            entry: Zu speichernder JournalEntry.
        """
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO journal_entries
                    (id, date, timestamp, entry_type, title, content,
                     tool_name, task_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.date,
                    entry.timestamp,
                    entry.entry_type,
                    entry.title,
                    entry.content,
                    entry.tool_name,
                    entry.task_id,
                    json.dumps(entry.metadata, ensure_ascii=False),
                ),
            )
        logger.debug("Journal-Eintrag gespeichert: %s", entry.id)

    def load_today(self) -> list[JournalEntry]:
        """Gibt alle Journal-Einträge des heutigen Tages zurück.

        Returns:
            Journal-Einträge von heute, nach Zeitstempel aufsteigend sortiert.
        """
        return self.load_by_date(_today())

    def load_by_date(self, date: str) -> list[JournalEntry]:
        """Gibt alle Journal-Einträge eines bestimmten Datums zurück.

        Args:
            date: Datum im Format ``"YYYY-MM-DD"``.

        Returns:
            Journal-Einträge des angegebenen Tages, nach Zeitstempel sortiert.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM journal_entries
                WHERE date = ?
                ORDER BY timestamp ASC
                """,
                (date,),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def load_recent(self, limit: int = 20) -> list[JournalEntry]:
        """Gibt die neuesten Journal-Einträge zurück.

        Args:
            limit: Maximale Anzahl zurückzugebender Einträge (Standard: 20).

        Returns:
            Neueste Journal-Einträge, nach Zeitstempel absteigend sortiert.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM journal_entries
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # -----------------------------------------------------------------------
    # Schnellstart / Tool-Nutzung
    # -----------------------------------------------------------------------

    def save_tool_used(self, tool_name: str, app_id: str = "finlai") -> None:
        """Speichert einen Tool-Aufruf für den Schnellzugriff.

        Args:
            tool_name: Name des aufgerufenen Tools.
            app_id: App-Kennung (z.B. "finlai", "norisk", "automate").
        """
        if not tool_name or not tool_name.strip():
            return
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO recent_tools (tool_name, used_at, app_id) VALUES (?, ?, ?)",
                (tool_name.strip(), _now_iso(), app_id),
            )
        logger.debug("Tool-Nutzung gespeichert: %s (%s)", tool_name, app_id)

    def load_recent_tools(self, limit: int = 5, app_id: str = "finlai") -> list[str]:
        """Gibt die zuletzt genutzten Tool-Namen zurück (eindeutig, nach App gefiltert).

        Args:
            limit: Maximale Anzahl zurückzugebender Tools (Standard: 5).
            app_id: Nur Tools dieser App zurückgeben.

        Returns:
            Eindeutige Tool-Namen, zuletzt genutzte zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT tool_name
                FROM recent_tools
                WHERE app_id = ?
                GROUP BY tool_name
                ORDER BY MAX(used_at) DESC
                LIMIT ?
                """,
                (app_id, limit),
            ).fetchall()
        return [r[0] for r in rows]

    # -----------------------------------------------------------------------
    # Interne Hilfsmethoden
    # -----------------------------------------------------------------------

    @staticmethod
    def _row_to_task(row: tuple) -> Task:
        """Konvertiert eine DB-Zeile zu einer Task-Instanz.

        Wir lesen Spalten **per Index**, damit die Migration in S2a (neue
        Felder hinten angefügt) ohne Cursor-Pflege funktioniert. Tabellen-
        Zeilen sind nach SELECT * in der Reihenfolge der ``CREATE TABLE``-
        Spalten + ``ALTER TABLE``-Anhänge sortiert; Sprint-Migrations ergänzen
        also stabil hinten — bestehende Indizes 0..11 bleiben unverändert.

        Args:
            row: Ergebniszeile aus der tasks-Tabelle (sqlite3.Row oder Tuple).

        Returns:
            Task-Instanz mit allen Feldern.
        """
        # Hilfsroutine: liest einen Index, gibt Default zurück wenn die
        # Zeile noch keine Spalte hat (z. B. unmittelbar nach einem
        # Schema-Roll-Forward auf einer alten DB-Datei, in der die
        # Migration noch nicht durchgelaufen ist — defensiv).
        def _at(idx: int, default: object = "") -> object:
            try:
                value = row[idx]
            except (IndexError, KeyError):
                return default
            return default if value is None else value

        return Task(
            id=str(_at(0)),
            title=str(_at(1)),
            description=str(_at(2, "")),
            status=str(_at(3, "open")),
            category=str(_at(4, "allgemein")),
            source=str(_at(5, "manual")),
            source_tool=str(_at(6, "")),
            klient=str(_at(7, "")),
            priority=str(_at(8, "normal")),
            created_at=str(_at(9, "")),
            updated_at=str(_at(10, "")),
            done_at=str(_at(11, "")),
            # Sprint S2a — neue Spalten (Index 12..17). Wenn die Spalten
            # noch nicht migriert sind, greifen die Defaults.
            urgency=str(_at(12, "mittel")),
            snoozed_until=str(_at(13, "")),
            pinned=bool(_at(14, 0)),
            evidence_refs=_decode_evidence_refs(_at(15, "[]")),
            dismissed_reason=str(_at(16, "")),
            dedup_key=str(_at(17, "")),
            # Index 18 (append-only Migration).
            done_note=str(_at(18, "")),
        )

    @staticmethod
    def _row_to_entry(row: tuple) -> JournalEntry:
        """Konvertiert eine DB-Zeile zu einem JournalEntry.

        Args:
            row: Ergebniszeile aus der journal_entries-Tabelle.

        Returns:
            JournalEntry-Instanz mit allen Feldern.
        """
        (
            eid,
            date,
            timestamp,
            entry_type,
            title,
            content,
            tool_name,
            task_id,
            metadata_raw,
        ) = row
        try:
            metadata = json.loads(metadata_raw or "{}")
        except (json.JSONDecodeError, TypeError):
            metadata = {}
        return JournalEntry(
            id=eid,
            date=date,
            timestamp=timestamp,
            entry_type=entry_type,
            title=title,
            content=content or "",
            tool_name=tool_name or "",
            task_id=task_id or "",
            metadata=metadata,
        )
