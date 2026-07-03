"""
ki_todo_anleitung_dialog — kuratierte Anleitung zu einem "FINLAI empfiehlt"-Todo
(c2, 2026-06-26).

Klickt der User eine KI-Todo-Karte, oeffnet dieser Dialog statt einer fragilen
Hover-/Frei-LLM-Erklaerung eine KURATIERTE Anleitung:
  1. der Befund selbst (Erklaerung + naechster Schritt — deterministisch aus dem
     Task, kein LLM -> keine Halluzination),
  2. passende Marketing-Leitfaden-PDFs zum Oeffnen (core.guide_registry),
  3. Hinweis auf den FINLAI-Assistenten (F1 / Maskottchen, lokal),
  4. Disclaimer, dass die lokale KI sich bei kritischen Schritten irren kann.

FINLAI-konformer Dialog (dialog-skill: kein ``QMessageBox``) — gleiche
Konventionen wie ``core.dialogs.FinlaiInfoDialog`` (frameless, modal, Raleway,
Akzent-Button, untrusted Text als PlainText).

Schichtzugehoerigkeit: gui/ — darf core + domain importieren.

Author: Patrick Riederich
Version: 1.0 (c2)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.branding import robot_pixmap
from core.guide_registry import (
    GuideEntry,
    fallback_guide,
    guide_path,
    match_guides,
)
from core.logger import get_logger
from tools.mainpage.domain.models import Task

_log = get_logger(__name__)

_DISCLAIMER = (
    "Hinweis: Der FINLAI-Assistent läuft als lokale KI und kann sich bei "
    "sicherheitskritischen Schritten irren. Verlasse dich bei kritischen "
    "Entscheidungen auf die Leitfäden oben oder die Hilfe (F1)."
)
_ASSISTENT_HINWEIS = (
    "Mehr Hilfe? Drücke F1 oder klicke das Maskottchen — der FINLAI-Assistent "
    "beantwortet deine Fragen lokal."
)


def _guides_fuer_task(task: Task) -> list[GuideEntry]:
    """Passende Leitfaden zum Task; faellt auf den Grundschutz-Leitfaden zurueck."""
    text = f"{task.title} {task.description} {task.source_tool or ''}"
    treffer = match_guides(text)
    if treffer:
        return treffer
    fb = fallback_guide()
    return [fb] if fb is not None else []


class KiTodoAnleitungDialog(QDialog):
    """Kuratierte Anleitung + Leitfaden-Verweise zu einem KI-Todo (c2)."""

    def __init__(self, task: Task, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._task = task
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self.setMinimumWidth(460)
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header: Maskottchen + "FINLAI empfiehlt"
        header = QHBoxLayout()
        header.setSpacing(10)
        robot = robot_pixmap(28)
        if not robot.isNull():
            robot_lbl = QLabel()
            robot_lbl.setPixmap(robot)
            robot_lbl.setStyleSheet("background: transparent; border: none;")
            header.addWidget(robot_lbl)
        head_lbl = QLabel("FINLAI empfiehlt")
        head_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_H3}px; "
            f"font-weight: 700; color: {c.ACCENT}; background: transparent;"
        )
        header.addWidget(head_lbl)
        header.addStretch()
        root.addLayout(header)

        # Titel des Befunds (untrusted -> PlainText, R22).
        title_lbl = QLabel(self._task.title)
        title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_LG}px; "
            f"font-weight: 700; color: {c.TEXT_MAIN}; background: transparent;"
        )
        root.addWidget(title_lbl)

        # Befund-Beschreibung (deterministisch aus dem Task; untrusted -> PlainText).
        if self._task.description:
            desc_lbl = QLabel(self._task.description)
            desc_lbl.setTextFormat(Qt.TextFormat.PlainText)
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet(
                f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; "
                f"color: {c.TEXT_DIM}; background: transparent;"
            )
            root.addWidget(desc_lbl)

        # Leitfaden-Buttons (falls vorhanden/gebuendelt).
        guides = _guides_fuer_task(self._task)
        if guides:
            lf_titel = QLabel("Passende Leitfäden:")
            lf_titel.setStyleSheet(
                f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_CAPTION}px; "
                f"font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; "
                f"color: {c.TEXT_DIM}; background: transparent; padding-top: 4px;"
            )
            root.addWidget(lf_titel)
            for entry in guides:
                root.addWidget(self._guide_button(entry, c))

        # Assistent-Hinweis.
        assist_lbl = QLabel(f"💬  {_ASSISTENT_HINWEIS}")
        assist_lbl.setWordWrap(True)
        assist_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_SM}px; "
            f"color: {c.TEXT_MAIN}; background: transparent; padding-top: 4px;"
        )
        root.addWidget(assist_lbl)

        # Disclaimer (Akzentlinie links).
        disc_lbl = QLabel(_DISCLAIMER)
        disc_lbl.setWordWrap(True)
        disc_lbl.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_CAPTION}px; "
            f"color: {c.TEXT_DIM}; background: {c.BG_INPUT}; "
            f"border-left: 3px solid {theme.WARNING_ORANGE}; "
            f"border-radius: 4px; padding: 8px 10px;"
        )
        root.addWidget(disc_lbl)

        # Schliessen-Button.
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton("Schließen")
        btn_close.setDefault(True)
        btn_close.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK}; border: none;"
            f" border-radius: 6px; padding: 7px 18px; font-family: 'Raleway';"
            f" font-weight: 600; font-size: {theme.FONT_SIZE_BODY}px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DIM}; color: {c.BG_DARK}; }}"
        )
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        root.addLayout(btn_row)

    def _guide_button(self, entry: GuideEntry, c) -> QPushButton:  # noqa: ANN001
        """Button, der den Leitfaden-PDF im Standard-Viewer oeffnet."""
        btn = QPushButton(f"📄  {entry.title} öffnen")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            f"QPushButton {{ text-align: left; background: {c.BG_INPUT}; "
            f"color: {c.TEXT_MAIN}; border: 1px solid {c.BORDER}; "
            f"border-radius: 4px; padding: 7px 12px; font-family: 'Raleway'; "
            f"font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
            f"QPushButton:hover {{ border-color: {c.ACCENT}; color: {c.ACCENT}; }}"
        )
        btn.clicked.connect(lambda: self._open_guide(entry))
        return btn

    def _open_guide(self, entry: GuideEntry) -> None:
        """Oeffnet das Leitfaden-PDF im Standard-Viewer (lokal, kein Netz)."""
        pfad = guide_path(entry)
        if not pfad.is_file():
            _log.warning("Leitfaden-PDF nicht gefunden: %s", pfad)
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(pfad)))
