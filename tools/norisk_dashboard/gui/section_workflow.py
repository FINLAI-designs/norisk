"""section_workflow — Der Cockpit-Workflow-Tab, Phase 3).

Der 4. Cockpit-Reiter: ein gefuehrter Leitfaden durch NoRisk. Zeigt die
Checkliste des aktuellen Subjekts (eigenes System oder Kunde) als Phasen-Pfad —
aufklappbare Phasen mit Schritt-Karten, oben ein Gesamt-Fortschrittsbalken. Je
Schritt: veraenderbarer Status, Notiz, Sprung zum Tool.

Kein DB-Zugriff im Konstruktor (Perf §6): die Daten kommen erst ueber
:meth:`load` (vom Dashboard beim ersten Tab-Oeffnen + bei Subjekt-Wechsel).

Schicht: ``gui/`` — die Fachlogik liegt im injizierten:class:`WorkflowService`.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiConfirmDialog
from core.logger import get_logger
from core.security_subject.models import Subject
from core.widgets.button_styles import (
    primary_button_qss,
    secondary_button_qss,
)
from core.widgets.finlai_progress import FinlaiProgressBar
from core.widgets.section import Section
from tools.norisk_dashboard.application.workflow_service import (
    WorkflowService,
    WorkflowView,
)
from tools.norisk_dashboard.gui._workflow_step_card import WorkflowStepCard

_log = get_logger(__name__)


class WorkflowTabWidget(QWidget):
    """Der Workflow-Tab (Phasen-Pfad + Fortschritt).

    Signals:
        navigate(str): Weiterleitung eines „Zum Tool"-Sprungs (nav_key).
    """

    navigate = Signal(str)

    def __init__(
        self, service: WorkflowService | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._subject: Subject | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        c = theme.get()
        # Selektor-gebunden (ObjectName): ein selektorloses ``background: …``
        # kaskadiert sonst in alle Kind-Widgets.
        self.setObjectName("workflowTab")
        self.setStyleSheet(f"#workflowTab {{ background: {c.BG_MAIN}; }}")
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 24)
        root.setSpacing(12)

        title = QLabel("Ihr Weg durch NoRisk")
        title.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-weight: 700;"
            f" font-size: 18px;"
        )

        intro = QLabel(
            "Diese Schritte führen Sie in der richtigen Reihenfolge durch NoRisk "
            "— erst prüfen und scannen, dann bewerten, schließlich nachweisen. "
            "Setzen Sie je Schritt einen Status und notieren Sie Offenes."
        )
        intro.setTextFormat(Qt.TextFormat.PlainText)
        intro.setWordWrap(True)
        intro.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
        )

        self._reset_btn = QPushButton("Zurücksetzen")
        self._reset_btn.setStyleSheet(secondary_button_qss())
        self._reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_btn.setToolTip(
            "Setzt Status und Notizen aller Schritte für dieses Subjekt zurück."
        )
        self._reset_btn.clicked.connect(self._on_reset_clicked)

        head_row = QHBoxLayout()
        head_row.addWidget(title)
        head_row.addStretch()
        head_row.addWidget(self._reset_btn)
        root.addLayout(head_row)
        root.addWidget(intro)

        # Subjekt-Echo + Fortschritt.
        self._subject_label = QLabel("")
        self._subject_label.setTextFormat(Qt.TextFormat.PlainText)
        self._subject_label.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-weight: 600;"
            f" font-size: 13px;"
        )
        root.addWidget(self._subject_label)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(10)
        self._progress = FinlaiProgressBar(total=100)
        progress_row.addWidget(self._progress, stretch=1)
        self._percent_label = QLabel("0 %")
        self._percent_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        progress_row.addWidget(self._percent_label)
        root.addLayout(progress_row)

        # Body: hier landen die Phasen-Sektionen (dynamisch bei load).
        self._body = QVBoxLayout()
        self._body.setSpacing(10)
        root.addLayout(self._body)

        self._empty_label = QLabel(
            "Kein Subjekt ausgewählt oder noch keine Daten verfügbar."
        )
        self._empty_label.setTextFormat(Qt.TextFormat.PlainText)
        self._empty_label.setWordWrap(True)
        self._empty_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 13px;"
        )
        self._empty_label.setVisible(False)
        root.addWidget(self._empty_label)
        root.addStretch()

    # ------------------------------------------------------------------
    # Laden / Rendern
    # ------------------------------------------------------------------

    def load(self, subject: Subject | None) -> None:
        """Laedt den Workflow fuer ein Subjekt (vom Dashboard aufgerufen).

        Args:
            subject: Das aktuell gewaehlte Subjekt (eigenes System oder Kunde);
                ``None`` -> Hinweiszustand.
        """
        self._subject = subject
        if self._service is None or subject is None:
            self._show_empty()
            return
        try:
            view = self._service.get_view(subject)
        except Exception:  # noqa: BLE001 — Tab darf das Cockpit nie crashen
            # Echten Fehler NICHT als „kein Subjekt" verschleiern: sichtbar
            # loggen (der Hinweiszustand bleibt der fail-soft UI-Fallback).
            _log.exception(
                "Workflow-Ansicht konnte nicht geladen werden (subject=%s)",
                subject.subject_id[:8],
            )
            self._show_empty()
            return
        self._render(view)

    def _reload(self) -> None:
        """Neu laden nach einer Aenderung (Status/Notiz/Reset)."""
        self.load(self._subject)

    def _show_empty(self) -> None:
        self._clear_body()
        self._subject_label.setText("")
        self._progress.setValue(0)
        self._percent_label.setText("0 %")
        self._reset_btn.setEnabled(False)
        self._empty_label.setVisible(True)

    def _render(self, view: WorkflowView) -> None:
        self._clear_body()
        self._empty_label.setVisible(False)
        self._reset_btn.setEnabled(True)

        art = "Eigenes System" if view.is_self else "Kunde"
        self._subject_label.setText(f"Workflow für: {view.subject_name} ({art})")
        self._progress.setValue(view.summary.percent_done)
        self._percent_label.setText(
            f"{view.summary.percent_done} % — {view.summary.done} von "
            f"{view.summary.relevant} erledigt"
        )

        if not view.steps:
            # Kann bei aktivem Profil-Gating auftreten (alle Schritte ausgeblendet).
            hint = QLabel(
                "Für dieses Subjekt sind aktuell keine Workflow-Schritte "
                "vorgesehen. Prüfen Sie ggf. die Profil-Einstellung zum "
                "Anzeigen aller Module."
            )
            hint.setTextFormat(Qt.TextFormat.PlainText)
            hint.setWordWrap(True)
            hint.setStyleSheet(
                f"color: {theme.get().TEXT_DIM}; font-family: 'Raleway';"
                f" font-size: 13px;"
            )
            self._body.addWidget(hint)
            return

        # Schritte nach Phase gruppieren (Reihenfolge bleibt erhalten).
        phases: dict[str, list] = {}
        for sv in view.steps:
            phases.setdefault(sv.step.phase, []).append(sv)

        number = 0
        for phase, step_views in phases.items():
            done = sum(1 for sv in step_views if sv.status.value == "erledigt")
            section = Section(f"{phase} — {done}/{len(step_views)}", expanded=True)
            container = QWidget()
            col = QVBoxLayout(container)
            col.setContentsMargins(0, 0, 0, 0)
            col.setSpacing(8)
            for sv in step_views:
                number += 1
                card = WorkflowStepCard(sv, number)
                card.navigate.connect(self.navigate.emit)
                card.status_changed.connect(self._on_status_changed)
                card.note_requested.connect(self._on_note_requested)
                col.addWidget(card)
            section.set_content(container)
            self._body.addWidget(section)

    def _clear_body(self) -> None:
        while self._body.count():
            item = self._body.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------

    def _on_status_changed(self, step_key: str, status: str) -> None:
        if self._service is None or self._subject is None:
            return
        try:
            self._service.set_status(self._subject.subject_id, step_key, status)
        except Exception:  # noqa: BLE001 — Persistenz darf den Tab nicht crashen
            _log.exception(
                "Status konnte nicht gespeichert werden (step=%s, status=%s)",
                step_key,
                status,
            )
            return
        # Verzoegert neu rendern: die ausloesende Karte/das Menue nicht mitten in
        # der Signalverarbeitung zerstoeren (Muster wie im Patch-Monitor).
        QTimer.singleShot(0, self._reload)

    def _on_note_requested(self, step_key: str) -> None:
        if self._service is None or self._subject is None:
            return
        current = ""
        try:
            progress = self._service.get_view(self._subject)
            for sv in progress.steps:
                if sv.step.step_key == step_key:
                    current = sv.note
                    break
        except Exception:  # noqa: BLE001 — Vorbelegung ist optional
            _log.exception(
                "Notiz-Vorbelegung fehlgeschlagen (step=%s)", step_key
            )
            current = ""
        dialog = _NoteDialog(current, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.set_note(self._subject.subject_id, step_key, dialog.text())
        except Exception:  # noqa: BLE001 — Persistenz darf den Tab nicht crashen
            _log.exception("Notiz konnte nicht gespeichert werden (step=%s)", step_key)
            return
        self._reload()

    def _on_reset_clicked(self) -> None:
        if self._service is None or self._subject is None:
            return
        dialog = FinlaiConfirmDialog(
            title="Workflow zurücksetzen",
            message="Status und Notizen aller Schritte für dieses Subjekt "
            "werden gelöscht. Das lässt sich nicht rückgängig machen.",
            confirm_text="Zurücksetzen",
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._service.reset(self._subject.subject_id)
        except Exception:  # noqa: BLE001 — Persistenz darf den Tab nicht crashen
            _log.exception(
                "Workflow-Reset fehlgeschlagen (subject=%s)",
                self._subject.subject_id[:8],
            )
            return
        self._reload()


class _NoteDialog(QDialog):
    """Kleiner Editor fuer die Schritt-Notiz (ein Feld, zwei Buttons)."""

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Notiz")
        self.setModal(True)
        self.setMinimumWidth(460)
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background: {c.CARD_BG}; border: 1px solid {c.BORDER};"
            f" border-radius: 8px; }}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)

        heading = QLabel("Notiz zum Schritt")
        heading.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-weight: 700;"
            f" font-size: {theme.FONT_SIZE_H3}px;"
        )
        root.addWidget(heading)

        self._edit = QPlainTextEdit()
        self._edit.setPlainText(text)
        self._edit.setMinimumHeight(140)
        self._edit.setPlaceholderText(
            "Was ist zu diesem Schritt offen oder erledigt?"
        )
        root.addWidget(self._edit)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Abbrechen")
        cancel.setStyleSheet(secondary_button_qss())
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        save = QPushButton("Speichern")
        save.setStyleSheet(primary_button_qss())
        save.setDefault(True)
        save.clicked.connect(self.accept)
        buttons.addWidget(save)
        root.addLayout(buttons)

    def text(self) -> str:
        """Der eingegebene Notiztext (getrimmt)."""
        return self._edit.toPlainText().strip()


__all__ = ["WorkflowTabWidget"]
