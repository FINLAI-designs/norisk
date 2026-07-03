"""
models — Datenmodelle des Mainpage-Dashboards.

Enthält alle Dataclasses für Aufgaben (Task), Tagesprotokoll
(JournalEntry), Changelog-Einträge (ChangelogEntry) und
das aggregierte Dashboard-Datenobjekt (DashboardData).

Keine externen Abhängigkeiten — ausschließlich Python-Standardbibliothek.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.exceptions import ValidationError

# ---------------------------------------------------------------------------
# Erlaubte Enum-artige Werte
# ---------------------------------------------------------------------------
# "dismissed" = vom User abgelehnte Aufgabe — verschwindet vom
# Board, bleibt aber in der DB (Aufgabenlog + Dedup-Schutz gegen
# Wiederauferstehung derselben KI-Todo).
_VALID_TASK_STATUS = frozenset({"open", "in_progress", "done", "dismissed"})
_VALID_TASK_CATEGORY = frozenset({"tool", "klient", "allgemein"})
_VALID_TASK_SOURCE = frozenset({"manual", "auto", "evergreen"})
_VALID_TASK_PRIORITY = frozenset({"low", "normal", "high"})
# Sprint S2a: Effort-Klassifikation für KI-Todos. ``mittel`` ist der
# Default — die Klassifikator-Heuristiken (H1–H12 in
# ``core.rules.classifier``) verschieben in Quick oder Langfrist, wenn
# Indikatoren greifen.
_VALID_TASK_URGENCY = frozenset({"quick", "mittel", "langfrist"})
_VALID_ENTRY_TYPES = frozenset({"note", "task_done", "tool_used", "auto"})


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------


@dataclass
class Task:
    """Eine Aufgabe im Task-Board.

    Kann manuell erstellt oder automatisch aus FINLAI-Aktionen
    erzeugt werden.

    Attributes:
        id: Eindeutige UUID der Aufgabe.
        title: Kurztitel der Aufgabe.
        description: Optionale ausführliche Beschreibung.
        status: Bearbeitungsstatus.
            ``"open"`` — noch nicht begonnen.
            ``"in_progress"`` — in Bearbeitung.
            ``"done"`` — abgeschlossen.
            ``"dismissed"`` — vom User abgelehnt (nicht auf dem Board).
        category: Kategorisierung der Aufgabe.
            ``"tool"`` — werkzeugbezogen.
            ``"klient"`` — klientenbezogen.
            ``"allgemein"`` — sonstige Aufgaben.
        source: Herkunft der Aufgabe.
            ``"manual"`` — manuell vom Nutzer erstellt.
            ``"auto"`` — automatisch von FINLAI erzeugt.
        source_tool: Name des Tools das die Aufgabe erzeugt hat.
        klient: Klientenname falls die Aufgabe einem Klienten zugeordnet ist.
        priority: Priorität der Aufgabe.
            ``"low"`` | ``"normal"`` | ``"high"``.
        created_at: ISO-Zeitstempel der Erstellung.
        updated_at: ISO-Zeitstempel der letzten Änderung.
        done_at: ISO-Zeitstempel der Erledigung (leer wenn nicht erledigt).
    """

    id: str
    title: str
    description: str = ""
    status: str = "open"
    category: str = "allgemein"
    source: str = "manual"
    source_tool: str = ""
    klient: str = ""
    priority: str = "normal"
    created_at: str = ""
    updated_at: str = ""
    done_at: str = ""
    # Sprint S2a — Felder für die Regel-Engine und Dedup:
    urgency: str = "mittel"
    """Effort-Klassifikation aus :mod:`core.rules.classifier` —
    ``quick`` / ``mittel`` / ``langfrist``. Default ``mittel`` (siehe
    AI_TODO 4.2 Tiebreaker: konservativer)."""
    snoozed_until: str = ""
    """ISO-Zeitstempel — wenn gesetzt und in der Zukunft, blendet die
    UI die Task aus, bis die Frist abläuft."""
    pinned: bool = False
    """User-Pin — wird vom Sortier-Algorithmus oben gehalten."""
    evidence_refs: list[dict] = field(default_factory=list)
    """Quellen-Referenzen für KI-Todos. Jeder Eintrag:
    ``{"tool": str, "finding_id": str}`` (vgl. AI_TODO 5.3)."""
    dismissed_reason: str = ""
    """Wenn der User die Task verworfen hat: kurze Begründung. Wird vom
    Cool-Down-Mechanismus genutzt, damit dieselbe Quelle nicht sofort
    eine neue Task auslöst (AI_TODO 5.7)."""
    dedup_key: str = ""
    """Stabile Hash-Referenz aus ``tool + finding_type + finding_id``.
    Wird von :meth:`TaskService.create_auto_task` zur Idempotenz-
    Sicherung genutzt."""
    done_note: str = ""
    """Maschinell gesetzte Notiz bei automatischer Erledigung (T-353),
    z. B. "Automatisch erledigt — Update installiert". Leer bei
    manueller Erledigung; macht Auto-Abschlüsse im Aufgabenlog
    selbsterklärend."""

    def __post_init__(self) -> None:
        """Validiert Pflichtfelder und Enum-Werte."""
        if not self.id or not self.id.strip():
            raise ValidationError("Task.id darf nicht leer sein.")
        if not self.title or not self.title.strip():
            raise ValidationError("Task.title darf nicht leer sein.")
        if self.status not in _VALID_TASK_STATUS:
            raise ValidationError(
                f"Task.status '{self.status}' ungültig. "
                f"Erlaubt: {sorted(_VALID_TASK_STATUS)}"
            )
        if self.category not in _VALID_TASK_CATEGORY:
            raise ValidationError(
                f"Task.category '{self.category}' ungültig. "
                f"Erlaubt: {sorted(_VALID_TASK_CATEGORY)}"
            )
        if self.source not in _VALID_TASK_SOURCE:
            raise ValidationError(
                f"Task.source '{self.source}' ungültig. "
                f"Erlaubt: {sorted(_VALID_TASK_SOURCE)}"
            )
        if self.priority not in _VALID_TASK_PRIORITY:
            raise ValidationError(
                f"Task.priority '{self.priority}' ungültig. "
                f"Erlaubt: {sorted(_VALID_TASK_PRIORITY)}"
            )
        if self.urgency not in _VALID_TASK_URGENCY:
            raise ValidationError(
                f"Task.urgency '{self.urgency}' ungültig. "
                f"Erlaubt: {sorted(_VALID_TASK_URGENCY)}"
            )


# ---------------------------------------------------------------------------
# JournalEntry
# ---------------------------------------------------------------------------


@dataclass
class JournalEntry:
    """Ein Eintrag im Tagesprotokoll.

    Enthält manuelle Notizen und automatisch erfasste Aktivitäten.

    Attributes:
        id: Eindeutige UUID des Eintrags.
        date: Datum des Eintrags (``"YYYY-MM-DD"``).
        timestamp: Vollständiger ISO-Zeitstempel.
        entry_type: Art des Eintrags.
            ``"note"`` — manuelle Notiz des Nutzers.
            ``"task_done"`` — eine Task wurde als erledigt markiert.
            ``"tool_used"`` — ein Tool wurde verwendet.
            ``"auto"`` — automatisch aus dem Audit-Log übernommen.
        title: Kurztitel des Eintrags.
        content: Optionaler Langtext / Notizinhalt.
        tool_name: Name des betroffenen Tools (leer wenn nicht zutreffend).
        task_id: UUID der verknüpften Task (leer wenn nicht zutreffend).
        metadata: Zusatzdaten abhängig vom Eintragstyp.
    """

    id: str
    date: str
    timestamp: str
    entry_type: str
    title: str
    content: str = ""
    tool_name: str = ""
    task_id: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validiert Pflichtfelder und Eintragstyp."""
        if not self.id or not self.id.strip():
            raise ValidationError("JournalEntry.id darf nicht leer sein.")
        if not self.date or not self.date.strip():
            raise ValidationError("JournalEntry.date darf nicht leer sein.")
        if not self.timestamp or not self.timestamp.strip():
            raise ValidationError("JournalEntry.timestamp darf nicht leer sein.")
        if self.entry_type not in _VALID_ENTRY_TYPES:
            raise ValidationError(
                f"JournalEntry.entry_type '{self.entry_type}' ungültig. "
                f"Erlaubt: {sorted(_VALID_ENTRY_TYPES)}"
            )
        if not self.title or not self.title.strip():
            raise ValidationError("JournalEntry.title darf nicht leer sein.")


# ---------------------------------------------------------------------------
# ChangelogEntry
# ---------------------------------------------------------------------------


@dataclass
class ChangelogEntry:
    """Ein Eintrag aus CHANGELOG.md.

    Attributes:
        version: Versionsnummer (z. B. ``"1.0.0"``).
        date: Veröffentlichungsdatum (``"YYYY-MM-DD"``).
        added: Liste neuer Funktionen.
        changed: Liste geänderter Funktionen.
        fixed: Liste behobener Fehler.
        security: Liste sicherheitsrelevanter Änderungen.
    """

    version: str
    date: str
    added: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validiert Pflichtfelder."""
        if not self.version or not self.version.strip():
            raise ValidationError("ChangelogEntry.version darf nicht leer sein.")


# ---------------------------------------------------------------------------
# DashboardData
# ---------------------------------------------------------------------------


@dataclass
class DashboardData:
    """Aggregiertes Datenobjekt für das Dashboard.

    Enthält alle für die Startseite benötigten Daten in einer
    einzelnen, kohärenten Datenstruktur.

    Attributes:
        user_name: Anzeigename des angemeldeten Nutzers.
        greeting: Tageszeit-abhängige Begrüßung (z. B. ``"Guten Morgen"``).
        current_time: Aktuelle Uhrzeit als String (z. B. ``"09:42"``).
        current_date: Aktuelles Datum (z. B. ``"Montag, 17. März 2026"``).
        tasks_open: Liste offener Aufgaben (status="open").
        tasks_in_progress: Liste laufender Aufgaben (status="in_progress").
        tasks_done_today: Heute erledigte Aufgaben (status="done").
        journal_today: Alle Journaleinträge des heutigen Tages.
        recent_activity: Letzte 10 Aktivitäten aus dem Audit-Log.
        changelog_entries: Letzte 3 Versionseinträge aus CHANGELOG.md.
        quick_tools: Letzte 5 genutzte Tool-Namen für Schnellzugriff.
    """

    user_name: str
    greeting: str
    current_time: str
    current_date: str
    tasks_open: list[Task]
    tasks_in_progress: list[Task]
    tasks_done_today: list[Task]
    journal_today: list[JournalEntry]
    recent_activity: list[JournalEntry]
    changelog_entries: list[ChangelogEntry]
    quick_tools: list[str]
