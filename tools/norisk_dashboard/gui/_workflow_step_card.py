"""_workflow_step_card — Eine Schritt-Karte im Cockpit-Workflow-Tab, Phase 3).

Eine Karte pro Workflow-Schritt: Nummer, Titel, Kurzbeschreibung, ein
veraenderbarer Status (Menue mit den fuenf Zustaenden), eine Notiz (Vorschau +
Bearbeiten) und ein „Zum Tool"-Sprung. Der linke Rand ist in der Statusfarbe
eingefaerbt (grafische Orientierung statt Liste).

Reine Presentation: die Karte haelt keinen Service, sondern meldet Aktionen ueber
Signale nach oben (``navigate`` / ``status_changed`` / ``note_requested``).

Schicht: ``gui/``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.widgets.button_styles import (
    link_button_qss,
    menu_qss,
    outline_button_qss,
    status_button_qss,
)
from tools.norisk_dashboard.application.workflow_service import WorkflowStepView
from tools.norisk_dashboard.domain.workflow_models import WorkflowStepStatus

#: Statuswert -> Anzeigetext (Sie-Form, Status ist zusaetzlich Text, nicht nur Farbe).
_STATUS_LABEL: dict[str, str] = {
    WorkflowStepStatus.OFFEN.value: "Offen",
    WorkflowStepStatus.IN_ARBEIT.value: "In Arbeit",
    WorkflowStepStatus.ERLEDIGT.value: "Erledigt",
    WorkflowStepStatus.UEBERSPRUNGEN.value: "Übersprungen",
    WorkflowStepStatus.NICHT_RELEVANT.value: "Nicht relevant",
}


def _status_color(status: str) -> str:
    """Statusfarbe aus Theme-Token (Erledigt = SUCCESS-Gruen, nicht Teal)."""
    c = theme.get()
    if status == WorkflowStepStatus.ERLEDIGT.value:
        return c.SUCCESS
    if status == WorkflowStepStatus.IN_ARBEIT.value:
        return theme.DARK_ACCENT
    return c.TEXT_DIM


class WorkflowStepCard(QFrame):
    """Karte eines Workflow-Schritts.

    Signals:
        navigate(str): „Zum Tool" — der nav_key des Ziel-Tools.
        status_changed(str, str): (step_key, neuer Statuswert).
        note_requested(str): step_key — Nutzer moechte die Notiz bearbeiten.
    """

    navigate = Signal(str)
    status_changed = Signal(str, str)
    note_requested = Signal(str)

    def __init__(
        self, view: WorkflowStepView, number: int, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._view = view
        self._number = number
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        step = self._view.step
        status_value = self._view.status.value
        accent = _status_color(status_value)

        self.setObjectName("workflowStepCard")
        self.setStyleSheet(
            f"#workflowStepCard {{ background: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER};"
            f" border-left: 4px solid {accent};"
            f" border-radius: 6px; }}"
        )
        # Barrierefreiheit: Screenreader liest Schritt-Titel + Status.
        self.setAccessibleName(f"Workflow-Schritt {self._number}: {step.titel}")
        self.setAccessibleDescription(
            f"{_STATUS_LABEL.get(status_value, status_value)} — {step.beschreibung}"
        )

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(12)

        # Nummer-Badge (Kreis).
        badge = QLabel(str(self._number))
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedSize(28, 28)
        badge.setStyleSheet(
            f"color: {c.TEXT_MAIN}; background: {c.BG_INPUT};"
            f" border: 1px solid {accent}; border-radius: 14px;"
            f" font-family: 'Raleway'; font-weight: 700; font-size: 13px;"
        )
        row.addWidget(badge, alignment=Qt.AlignmentFlag.AlignTop)

        # Mitte: Titel + Beschreibung + Notiz-Vorschau.
        mid = QVBoxLayout()
        mid.setSpacing(2)

        title = QLabel(step.titel)
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setWordWrap(True)
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-weight: 700;"
            f" font-size: {theme.FONT_SIZE_H3}px;"
        )
        mid.addWidget(title)

        desc = QLabel(step.beschreibung)
        desc.setTextFormat(Qt.TextFormat.PlainText)
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        mid.addWidget(desc)

        if self._view.note:
            preview = self._view.note.splitlines()[0][:80]
            note_lbl = QLabel(f"Notiz: {preview}")
            note_lbl.setTextFormat(Qt.TextFormat.PlainText)
            note_lbl.setWordWrap(True)
            note_lbl.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 11px;"
                f" font-style: italic;"
            )
            mid.addWidget(note_lbl)
        row.addLayout(mid, stretch=1)

        # Rechts: Status-Menue, Notiz-Button, Zum-Tool-Button.
        right = QVBoxLayout()
        right.setSpacing(6)
        right.addWidget(self._build_status_button(status_value, accent))

        note_btn = QPushButton(
            "Notiz bearbeiten" if self._view.note else "Notiz hinzufügen"
        )
        note_btn.setStyleSheet(link_button_qss())
        note_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        note_btn.clicked.connect(
            lambda: self.note_requested.emit(step.step_key)
        )
        right.addWidget(note_btn)

        goto = QPushButton("Zum Tool →")
        goto.setStyleSheet(outline_button_qss())
        goto.setCursor(Qt.CursorShape.PointingHandCursor)
        goto.clicked.connect(lambda: self.navigate.emit(step.nav_key))
        right.addWidget(goto)

        row.addLayout(right)

    def _build_status_button(self, status_value: str, accent: str) -> QToolButton:
        btn = QToolButton()
        btn.setText(_STATUS_LABEL.get(status_value, status_value))
        btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setToolTip("Status ändern")
        # Zentrale Factory (alle vier States, kaskaden-robust) mit der
        # bedeutungstragenden Statusfarbe — keine Ad-hoc-QSS mehr (R26/frontend-design).
        btn.setStyleSheet(status_button_qss(accent))
        btn.setAccessibleName("Status ändern")

        menu = QMenu(btn)
        menu.setStyleSheet(menu_qss())
        for value, label in _STATUS_LABEL.items():
            action = QAction(label, menu)
            action.setData(value)
            action.triggered.connect(
                lambda _checked=False, v=value: self.status_changed.emit(
                    self._view.step.step_key, v
                )
            )
            menu.addAction(action)
        btn.setMenu(menu)
        return btn


__all__ = ["WorkflowStepCard"]
