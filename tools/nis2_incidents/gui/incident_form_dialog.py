"""incident_form_dialog — Modal-Dialog zum Anlegen eines NIS2-Vorfalls.

Felder:
- Titel (Pflicht)
- Schweregrad (LOW/MEDIUM/HIGH/CRITICAL)
- Erkennungs-Zeitpunkt (DateTimeEdit, Default: jetzt)
- Customer-Audit-Auswahl (Dropdown, Pflicht — Soft-FK audit_id)
- Beschreibung (mehrzeilig, optional)
- Bearbeiter (Single-Line, optional)

Validierung:
- Titel nicht leer
- audit_id nicht leer

ADR-Bezug: docs/adr/-nis2-incident-tracker.md.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from PySide6.QtCore import QDateTime, Qt, QTimeZone
from PySide6.QtWidgets import (
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import FinlaiInfoDialog
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons
from tools.customer_audit.domain.nis2_incident import IncidentSeverity
from tools.customer_audit.domain.nis2_phase_schema import PII_HINWEIS

_SEVERITY_OPTIONS: tuple[tuple[IncidentSeverity, str], ...] = (
    (IncidentSeverity.LOW, "LOW — geringer Vorfall"),
    (IncidentSeverity.MEDIUM, "MEDIUM — beachtenswert"),
    (IncidentSeverity.HIGH, "HIGH — erheblicher Vorfall"),
    (IncidentSeverity.CRITICAL, "CRITICAL — kritischer Vorfall"),
)


@dataclass(frozen=True)
class IncidentFormData:
    """Eingaben aus dem Anlage-Dialog (kein Domain-Objekt — Service baut das)."""

    audit_id: str
    title: str
    description: str
    severity: IncidentSeverity
    detected_at: datetime
    actor: str


class IncidentFormDialog(QDialog):
    """Modal-Dialog fuer einen neuen Vorfall.

    Konstruktor-Param ``audit_choices`` ist eine Liste von
    ``(audit_id, display_label)``-Tupeln — der Dialog fuehrt die Auswahl,
    der Caller hat die Liste vorbereitet (z.B. ueber den
    CustomerAuditService).
    """

    def __init__(
        self,
        audit_choices: Sequence[tuple[str, str]],
        parent: QWidget | None = None,
        *,
        default_audit_id: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Neuen NIS2-Vorfall anlegen")
        self.setMinimumWidth(520)
        self._audit_choices = list(audit_choices)
        self._build_ui(default_audit_id)

    def _build_ui(self, default_audit_id: str | None) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        intro = QLabel(
            "Erfassen Sie einen erheblichen Sicherheitsvorfall. Der "
            "Erkennungs-Zeitpunkt ist der Anker fuer die NIS2-Fristen "
            "(24h Early-Warning / 72h Notification / 30d Final-Report)."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        form.setSpacing(8)

        self._audit_combo = QComboBox()
        self._audit_combo.setObjectName("combo_audit")
        if not self._audit_choices:
            self._audit_combo.addItem(
                "Kein Customer-Audit vorhanden", userData=""
            )
            self._audit_combo.setEnabled(False)
        else:
            for audit_id, label in self._audit_choices:
                self._audit_combo.addItem(label, userData=audit_id)
            if default_audit_id is not None:
                idx = self._audit_combo.findData(default_audit_id)
                if idx >= 0:
                    self._audit_combo.setCurrentIndex(idx)
        form.addRow("Customer-Audit", self._with_help(self._audit_combo, "combo_audit"))

        self._title_input = QLineEdit()
        self._title_input.setObjectName("input_title")
        self._title_input.setMaxLength(200)
        self._title_input.setPlaceholderText(
            "z.B. Ransomware-Verdacht in der Buchhaltung"
        )
        form.addRow("Titel", self._with_help(self._title_input, "input_title"))

        self._severity_combo = QComboBox()
        self._severity_combo.setObjectName("combo_severity")
        for severity, label in _SEVERITY_OPTIONS:
            self._severity_combo.addItem(label, userData=severity)
        self._severity_combo.setCurrentIndex(2)  # Default HIGH
        form.addRow("Schweregrad", self._with_help(self._severity_combo, "combo_severity"))

        self._detected_edit = QDateTimeEdit()
        self._detected_edit.setObjectName("edit_detected")
        # NIS2-Fristen ankern in UTC: Widget in UTC fuehren, sonst wird naive
        # Lokalzeit faelschlich als UTC gestempelt (Frist-Skew um den lokalen
        # Offset)..
        self._detected_edit.setTimeZone(QTimeZone(QTimeZone.UTC))
        self._detected_edit.setDateTime(QDateTime.currentDateTimeUtc())
        self._detected_edit.setCalendarPopup(True)
        self._detected_edit.setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'")
        form.addRow("Erkannt am", self._with_help(self._detected_edit, "edit_detected"))

        self._description_input = QTextEdit()
        self._description_input.setObjectName("input_description")
        self._description_input.setAcceptRichText(False)
        self._description_input.setPlaceholderText(
            "Optional: 1-3 Saetze, was passiert ist und wer/was betroffen "
            "scheint."
        )
        self._description_input.setFixedHeight(80)
        form.addRow("Beschreibung", self._description_input)

        # PII-Hinweis fuer die Freitextfelder (Titel/Beschreibung) — derselbe
        # Hinweis wie im Phasenformular: Titel + Beschreibung wandern in den
        # (nur HMAC-, nicht pseudonymisierungs-)geschuetzten Trail §4).
        pii_hint = QLabel(PII_HINWEIS)
        pii_hint.setObjectName("lbl_pii_hinweis")
        pii_hint.setWordWrap(True)
        pii_hint.setTextFormat(Qt.TextFormat.PlainText)
        pii_hint.setStyleSheet(
            f"color: {theme.WARNING_ORANGE}; font-style: italic;"
        )
        form.addRow("", pii_hint)

        self._actor_input = QLineEdit()
        self._actor_input.setObjectName("input_actor")
        self._actor_input.setMaxLength(100)
        self._actor_input.setPlaceholderText(
            "Optional: Benutzername fuer den Audit-Trail"
        )
        form.addRow("Bearbeiter", self._actor_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("OK")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Abbrechen")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _with_help(self, widget: QWidget, tooltip_key: str) -> QWidget:
        """Verpackt ein Form-Widget mit einem HelpButton, wenn ein Tooltip registriert ist."""
        hc = HelpRegistry.get("nis2_incidents")
        tip = hc.tooltips.get(tooltip_key, "") if hc else ""
        if not tip:
            return widget
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(widget, stretch=1)
        layout.addWidget(HelpButton(tip, title="NIS2-Vorfall — Feldhilfe"))
        return row

    def _on_accept(self) -> None:
        if not self._title_input.text().strip():
            FinlaiInfoDialog(
                title="Eingabe unvollstaendig",
                message="Bitte geben Sie einen Titel fuer den Vorfall ein.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            self._title_input.setFocus()
            return
        if not self._audit_combo.currentData():
            FinlaiInfoDialog(
                title="Customer-Audit fehlt",
                message="Bitte legen Sie zuerst einen Customer-Audit an.",
                icon_name=Icons.WARNING,
                parent=self,
            ).exec()
            return
        self.accept()

    def collected(self) -> IncidentFormData | None:
        """Liefert die ausgefuellten Daten, wenn der Dialog accepted wurde."""
        if self.result() != QDialog.DialogCode.Accepted:
            return None
        audit_id = str(self._audit_combo.currentData() or "")
        # StrEnum-userData kommt als plain str zurueck (Qt serialisiert ueber
        # QVariant): Enum daraus rekonstruieren, statt per isinstance-Check
        # still auf MEDIUM zu fallen..
        severity = IncidentSeverity(self._severity_combo.currentData())
        # toUTC erzwingt UTC-Wandzeit-Werte (robust gegen Spec-Drift),
        # toPython liefert sie naiv -> als aware UTC stempeln..
        qt_dt = self._detected_edit.dateTime().toUTC().toPython().replace(tzinfo=UTC)
        return IncidentFormData(
            audit_id=audit_id,
            title=self._title_input.text().strip(),
            description=self._description_input.toPlainText().strip(),
            severity=severity,
            detected_at=qt_dt,
            actor=self._actor_input.text().strip(),
        )
