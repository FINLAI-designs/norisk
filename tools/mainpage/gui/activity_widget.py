"""
activity_widget — Letzte-Aktivitäten-Widget des Mainpage-Dashboards.

Liest die letzten Einträge aus dem Audit-Log und zeigt sie an.
Auto-Refresh alle 60 Sekunden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.finlai_paths import finlai_dir
from core.logger import get_logger
from core.widgets.button_styles import link_button_qss, outline_button_qss

_log = get_logger(__name__)

_AUDIT_DIR = finlai_dir() / "audit"
# Kompakt-Liste auf dem Homescreen AP3: Aktivitaeten sind
# Sekundaer-Info unten rechts — 5 Zeilen, Rest im Dialog).
_MAX_ENTRIES = 5
# Hoehendeckel der Kompakt-Karte — Aktivitaeten duerfen nie wieder den
# Homescreen-Restraum fressen AP3).
_MAX_WIDGET_HOEHE = 200
# Eintraege in der "Alle anzeigen"-Vollansicht.
_DIALOG_LIMIT = 100


def _format_date_label(dt: datetime, *, today: datetime | None = None) -> str:
    """Liefert ein lesbares Datum-Label fuer einen Audit-Eintrag.

    "Heute" / "Gestern" / "TT.MM." — damit der Activity-Feed nicht mehr
    Eintraege von verschiedenen Tagen ohne sichtbare Trennung mischt.

    Args:
        dt: Zeitstempel des Audit-Eintrags.
        today: Optionaler Bezugszeitpunkt (Default: jetzt). Fuer Tests.

    Returns:
        ``"Heute"`` wenn dt am heutigen Datum, ``"Gestern"`` wenn am
        Vortag, sonst ``"TT.MM."``.
    """
    ref = today or datetime.now()
    delta = (ref.date() - dt.date()).days
    if delta == 0:
        return "Heute"
    if delta == 1:
        return "Gestern"
    return dt.strftime("%d.%m.")


def _read_recent_audit(limit: int = _MAX_ENTRIES) -> list[dict]:
    """Liest die neuesten Einträge aus dem Audit-Log.

    Args:
        limit: Maximale Anzahl zurückzugebender Einträge.

    Returns:
        Liste von Audit-Log-Dicts, neueste zuerst.
    """
    if not _AUDIT_DIR.exists():
        return []

    lines: list[str] = []
    # Aktuelle und vorherige Monats-Datei lesen
    for log_file in sorted(_AUDIT_DIR.glob("audit_*.log"), reverse=True)[:2]:
        try:
            file_lines = log_file.read_text(encoding="utf-8").splitlines()
            lines = file_lines + lines
        except OSError:
            pass

    entries: list[dict] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            entries.append(entry)
            if len(entries) >= limit:
                break
        except json.JSONDecodeError:
            pass

    return entries


class ActivityWidget(QWidget):
    """Zeigt die letzten Aktivitäten aus dem Audit-Log.

    Aktualisiert sich automatisch alle 60 Sekunden.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Aktivitäts-Widget.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        t = theme.get()
        self.setStyleSheet(
            f"background-color: {t.CARD_BG}; "
            f"border: 1px solid {t.BORDER}; border-radius: 4px;"
        )
        self.setMaximumHeight(_MAX_WIDGET_HOEHE)
        # Untergrenze, damit die Karte bei niedrigen Fenstern lesbar bleibt
        self.setMinimumHeight(120)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 8, 12, 8)
        outer.setSpacing(6)

        # Header
        hdr_row = QHBoxLayout()
        self._header_lbl = QLabel("Letzte Aktivitäten")
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-weight: bold; color: {t.ACCENT}; "
            f"background: transparent; border: none;"
        )
        hdr_row.addWidget(self._header_lbl)
        hdr_row.addStretch()
        outer.addLayout(hdr_row)

        self._sep1 = QFrame()
        self._sep1.setFrameShape(QFrame.Shape.HLine)
        self._sep1.setFixedHeight(1)
        self._sep1.setStyleSheet(f"background: {t.BORDER}; border: none;")
        outer.addWidget(self._sep1)

        # Scrollbarer Aktivitäts-Bereich
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        self._content = QWidget()
        self._content.setStyleSheet("background: transparent;")
        self._content_lyt = QVBoxLayout(self._content)
        self._content_lyt.setContentsMargins(0, 0, 0, 0)
        self._content_lyt.setSpacing(4)
        self._content_lyt.addStretch()

        scroll.setWidget(self._content)
        outer.addWidget(scroll)

        # [Alle anzeigen] — oeffnet die Vollansicht AP3, E4)
        self._sep2 = QFrame()
        self._sep2.setFrameShape(QFrame.Shape.HLine)
        self._sep2.setFixedHeight(1)
        self._sep2.setStyleSheet(f"background: {t.BORDER}; border: none;")
        outer.addWidget(self._sep2)

        self._btn_all = QPushButton("Alle anzeigen →")
        self._btn_all.setFixedHeight(22)
        self._btn_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_all.setStyleSheet(link_button_qss())
        self._btn_all.clicked.connect(self._zeige_alle)
        outer.addWidget(self._btn_all, alignment=Qt.AlignmentFlag.AlignRight)

        self._load_entries()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        from core import theme  # noqa: PLC0415

        c = theme.get()
        self.setStyleSheet(
            f"background-color: {c.CARD_BG}; "
            f"border: 1px solid {c.BORDER}; border-radius: 4px;"
        )
        self._header_lbl.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; "
            f"font-size: 13px; font-weight: bold; color: {c.ACCENT}; "
            f"background: transparent; border: none;"
        )
        self._sep1.setStyleSheet(f"background: {c.BORDER}; border: none;")
        self._sep2.setStyleSheet(f"background: {c.BORDER}; border: none;")
        self._btn_all.setStyleSheet(link_button_qss())
        self._load_entries()

    def _load_entries(self) -> None:
        """Lädt Audit-Log-Einträge und aktualisiert die Anzeige."""
        # Alte Einträge löschen (außer stretch)
        while self._content_lyt.count() > 1:
            item = self._content_lyt.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        entries = _read_recent_audit(limit=_MAX_ENTRIES)
        t = theme.get()

        if not entries:
            placeholder = QLabel("Keine Aktivitäten vorhanden.")
            placeholder.setStyleSheet(
                f"color: {t.TEXT_DIM}; font-size: 12px; background: transparent; border: none;"
            )
            self._content_lyt.insertWidget(0, placeholder)
            return

        for i, entry in enumerate(entries):
            row = self._build_row(entry)
            self._content_lyt.insertWidget(i, row)

    def _build_row(self, entry: dict) -> QWidget:
        """Baut eine einzelne Aktivitäts-Zeile auf.

        Args:
            entry: Audit-Log-Eintrag als Dict.

        Returns:
            QWidget mit Zeit, Tool und Aktion.
        """
        return _build_activity_row(entry)

    def _zeige_alle(self) -> None:
        """Öffnet die Vollansicht mit den letzten Aktivitäten AP3)."""
        dlg = ActivityDialog(parent=self.window())
        dlg.exec()

    def refresh(self) -> None:
        """Aktualisiert die Aktivitäts-Anzeige."""
        self._load_entries()


def _build_activity_row(entry: dict) -> QWidget:
    """Baut eine Aktivitäts-Zeile (Zeit | Tool | Aktion) — geteilt von
    Kompakt-Karte und Vollansicht-Dialog.

    Args:
        entry: Audit-Log-Eintrag als Dict.

    Returns:
        QWidget mit Zeit, Tool und Aktion.
    """
    t = theme.get()
    row = QWidget()
    row.setStyleSheet("background: transparent; border: none;")
    lyt = QHBoxLayout(row)
    lyt.setContentsMargins(0, 2, 0, 2)
    lyt.setSpacing(8)

    # Zeitstempel mit Datum-Label: "Heute 14:23" / "Gestern 04:41" /
    # "05.05. 20:52" — damit verschiedene Tage im Feed sichtbar getrennt sind.
    ts = entry.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts)
        time_str = f"{_format_date_label(dt)} {dt.strftime('%H:%M')}"
    except (ValueError, TypeError):
        time_str = ts[:5] if len(ts) >= 5 else "—"

    time_lbl = QLabel(time_str)
    time_lbl.setTextFormat(Qt.TextFormat.PlainText)
    time_lbl.setFixedWidth(80)
    time_lbl.setStyleSheet(
        f"font-size: 11px; color: {t.TEXT_DIM}; background: transparent; border: none;"
    )
    lyt.addWidget(time_lbl)

    # Tool
    tool = entry.get("tool") or "—"
    tool_lbl = QLabel(str(tool)[:14])
    tool_lbl.setTextFormat(Qt.TextFormat.PlainText)
    tool_lbl.setFixedWidth(90)
    tool_lbl.setStyleSheet(
        f"font-size: 11px; color: {t.ACCENT}; background: transparent; border: none;"
    )
    lyt.addWidget(tool_lbl)

    # Aktion — details-Werte sind untrusted (Usernames, URLs, Fehlertexte):
    # nie als Auto-RichText rendern (R22-Lehre).
    action = entry.get("action", "")
    details = entry.get("details") or {}
    detail_str = ", ".join(f"{v}" for v in details.values())[:40] if details else ""
    action_text = f"{action}  {detail_str}".strip()

    action_lbl = QLabel(action_text)
    action_lbl.setTextFormat(Qt.TextFormat.PlainText)
    action_lbl.setStyleSheet(
        f"font-size: 11px; color: {t.TEXT_MAIN}; background: transparent; border: none;"
    )
    lyt.addWidget(action_lbl)
    lyt.addStretch()

    return row


class ActivityDialog(QDialog):
    """Vollansicht der letzten Aktivitäten AP3, dialog-skill Typ C).

    Modal über dem Hauptfenster; zeigt bis zu ``_DIALOG_LIMIT``
    Audit-Einträge als scrollbare Liste. ``_read_recent_audit`` liest
    nur die zwei neuesten Monatsdateien — in jungen Monaten können es
    entsprechend weniger Einträge sein (das Sub-Label zeigt die echte
    Anzahl).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert den Aktivitäten-Dialog.

        Args:
            parent: Eltern-Widget (für Zentrierung/Modalität).
        """
        super().__init__(parent)
        t = theme.get()
        self.setWindowTitle("Alle Aktivitäten")
        self.setModal(True)
        self.setMinimumSize(560, 480)
        self.setMaximumWidth(600)
        self.setStyleSheet(f"background-color: {t.CARD_BG};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)

        entries = _read_recent_audit(limit=_DIALOG_LIMIT)

        titel = QLabel("Alle Aktivitäten")
        titel.setStyleSheet(
            f"font-family: 'Raleway', 'Segoe UI', sans-serif; font-size: 16px;"
            f" font-weight: bold; color: {t.TEXT_MAIN};"
            f" background: transparent; border: none;"
        )
        outer.addWidget(titel)

        sub = QLabel(
            f"Die letzten {len(entries)} Einträge aus dem Audit-Log."
            if entries
            else "Noch keine Einträge im Audit-Log."
        )
        sub.setStyleSheet(
            f"font-size: 12px; color: {t.TEXT_DIM};"
            f" background: transparent; border: none;"
        )
        outer.addWidget(sub)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background: {t.BORDER}; border: none;")
        outer.addWidget(sep)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content_lyt = QVBoxLayout(content)
        content_lyt.setContentsMargins(0, 0, 0, 0)
        content_lyt.setSpacing(4)
        if entries:
            for entry in entries:
                content_lyt.addWidget(_build_activity_row(entry))
        else:
            leer = QLabel("Keine Aktivitäten vorhanden.")
            leer.setStyleSheet(
                f"color: {t.TEXT_DIM}; font-size: 12px;"
                f" background: transparent; border: none;"
            )
            content_lyt.addWidget(leer)
        content_lyt.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_schliessen = QPushButton("Schließen")
        btn_schliessen.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_schliessen.setStyleSheet(outline_button_qss())
        btn_schliessen.clicked.connect(self.accept)
        btn_row.addWidget(btn_schliessen)
        outer.addLayout(btn_row)
