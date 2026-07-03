"""phase_form_dialog — Pro-Phase-Pflichtformular fuer den NIS2-Tracker.

Baut sich dynamisch aus
:func:`~tools.customer_audit.domain.nis2_phase_schema.fields_for` auf: je
:class:`~tools.customer_audit.domain.nis2_phase_schema.FieldType` wird das
passende Eingabe-Widget gerendert. Jedes Feld zeigt seinen ``help_text``
("Was-zu-tun") SICHTBAR (nicht nur als Tooltip); Freitext-/Listenfelder
zusaetzlich den:data:`~tools.customer_audit.domain.nis2_phase_schema.PII_HINWEIS`.

Zwei Aktionen §1/§2):

- **Entwurf speichern** — schreibt den aktuellen Payload via
  ``save_draft`` in die mutable Draft-Tabelle (keine Pflichtpruefung).
- **Phase einreichen** — validiert die Pflichtfelder via
:func:`nis2_phase_schema.validate`; bei fehlenden Feldern Inline-Fehler +
  Abbruch, sonst ``save_draft`` gefolgt von ``submit_draft(status=DONE)``
  (atomarer Draft → Append-only-Event im Service).

NOTIFICATION-Sonderfall: das ``personenbezug``-BOOL-Feld synchronisiert beim
Einreichen das harte Header-Flag (``set_personenbezug``) und blendet einen
Hinweis auf die parallele DSGVO-Art.33-72h-Frist ein.

Schichtzugehoerigkeit: gui/ — ruft application/ (Service) + domain/ (Schema),
nie data/ direkt (Hexagonal).

ADR-Bezug: docs/adr/-nis2-tracker-revisionssicher.md §1, §2, §4.

Author: Patrick Riederich
Version: 0.1 (NIS2-revisionssicher, Schicht 2 GUI)
"""

from __future__ import annotations

from datetime import UTC

from PySide6.QtCore import QDateTime, Qt, QTimeZone
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.domain import nis2_phase_schema
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    PhaseStatus,
)
from tools.customer_audit.domain.nis2_phase_schema import (
    PII_HINWEIS,
    FieldType,
    FormField,
)

_log = get_logger(__name__)

#: Tristate-Auswahl §1). userData = stabiler Payload-Wert.
_TRISTATE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("", "— bitte waehlen —"),
    ("ja", "Ja"),
    ("nein", "Nein"),
    ("unbekannt", "Unbekannt"),
)

#: Sichtbare Phasen-Anleitung (was muss in dieser Phase ans CSIRT, welche
#: Frist) — frueher nur Hover-Tooltip in der Timeline §1, Schritt 4).
_PHASE_GUIDANCE: dict[IncidentPhase, str] = {
    IncidentPhase.DETECT: (
        "Awareness des erheblichen Vorfalls. Halten Sie den Zeitpunkt der "
        "Kenntnisnahme fest — er verankert alle NIS2-Fristen (24h/72h/30d)."
    ),
    IncidentPhase.TRIAGE: (
        "Erst-Klassifikation und Eskalations-Entscheidung. Pruefen Sie, ob ein "
        "erheblicher Vorfall im NIS2-Sinn vorliegt — davon haengt die "
        "Meldepflicht ab."
    ),
    IncidentPhase.EARLY_WARNING: (
        "24h-Fruehwarnung gemaess NIS2 Art. 23 Abs. 4 (a). Innerhalb von 24h "
        "ab Kenntnisnahme an Ihr CSIRT (AT: nis.govcert.gv.at): Verdacht auf "
        "rechtswidrige Handlung? Grenzueberschreitende Auswirkungen?"
    ),
    IncidentPhase.NOTIFICATION: (
        "72h-Meldung an das CSIRT mit Erstbewertung des Schadensausmasses "
        "(Schweregrad, Auswirkungen, erste Ursache, IoCs). Bei Personenbezug "
        "laeuft PARALLEL die DSGVO-Art.33-72h-Frist an die Datenschutzbehoerde."
    ),
    IncidentPhase.FINAL_REPORT: (
        "30-Tage-Abschlussbericht an das CSIRT: vollstaendiger Hergang, "
        "endgueltige Ursache (Root Cause) und ergriffene/geplante Massnahmen."
    ),
    IncidentPhase.POST_INCIDENT: (
        "Lessons Learned und Follow-ups. Keine externe Meldepflicht mehr — "
        "interne Nachbereitung."
    ),
}

#: Hinweis auf die parallele DSGVO-Frist (NOTIFICATION-Phase §4).
_DSGVO_HINWEIS: str = (
    "Achtung: Bei Personenbezug laeuft parallel die DSGVO-Art.33-Frist — die "
    "Meldung an die Datenschutzbehoerde ist binnen 72h ab Kenntnisnahme faellig "
    "und unabhaengig von der NIS2-Meldung an das CSIRT."
)


class PhaseFormDialog(QDialog):
    """Modal-Dialog fuer das Pflichtformular einer einzelnen Incident-Phase.

    Rendert die Felder aus ``fields_for(phase)``, laedt einen bestehenden Draft
    und bietet "Entwurf speichern" + "Phase einreichen". Nach dem Schliessen
    liefern:meth:`collected_payload` und:meth:`chosen_action` das Ergebnis.

    Attributes:
        ACTION_NONE: Dialog abgebrochen/geschlossen ohne Aktion.
        ACTION_SAVED: Entwurf wurde gespeichert.
        ACTION_SUBMIT: Phase wurde eingereicht (Append-only-Event geschrieben).
    """

    ACTION_NONE = "none"
    ACTION_SAVED = "saved"
    ACTION_SUBMIT = "submitted"

    def __init__(
        self,
        incident_id: str,
        phase: IncidentPhase,
        service: Nis2IncidentService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._incident_id = incident_id
        self._phase = phase
        self._service = service
        self._fields = nis2_phase_schema.fields_for(phase)
        # key -> (FormField, value_getter, value_setter)
        self._widgets: dict[str, FormField] = {}
        self._getters: dict[str, object] = {}
        self._error_label: QLabel | None = None
        self._action = self.ACTION_NONE
        self._result_payload: dict = {}

        self.setWindowTitle(f"NIS2-Phase: {_phase_title(phase)}")
        self.setMinimumWidth(560)
        self._build_ui()
        self._load_existing_draft()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # Sichtbare Phasen-Anleitung (Schritt 4: Tooltip → sichtbar).
        guidance = QLabel(_PHASE_GUIDANCE.get(self._phase, ""))
        guidance.setObjectName("lbl_phase_guidance")
        guidance.setWordWrap(True)
        guidance.setTextFormat(Qt.TextFormat.PlainText)
        guidance.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; "
            f"background-color: {theme.DARK_BG_SECONDARY}; "
            f"border-left: 3px solid {theme.DARK_ACCENT}; "
            f"padding: 8px 10px; font-size: {theme.FONT_SIZE_BODY}px;"
        )
        root.addWidget(guidance)

        # Scrollbarer Feld-Bereich (lange Formulare wie NOTIFICATION).
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        fields_host = QWidget()
        self._fields_layout = QVBoxLayout(fields_host)
        self._fields_layout.setContentsMargins(0, 0, 0, 0)
        self._fields_layout.setSpacing(14)

        if not self._fields:
            empty = QLabel(
                "Diese Phase hat kein Pflichtformular. Sie kann direkt "
                "abgeschlossen werden."
            )
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {theme.DARK_TEXT_SECONDARY};")
            self._fields_layout.addWidget(empty)
        else:
            for field in self._fields:
                self._fields_layout.addWidget(self._build_field_block(field))

        self._fields_layout.addStretch(1)
        scroll.setWidget(fields_host)
        root.addWidget(scroll, stretch=1)

        # NOTIFICATION: paralleler DSGVO-Frist-Hinweis.
        if self._phase is IncidentPhase.NOTIFICATION:
            dsgvo = QLabel(_DSGVO_HINWEIS)
            dsgvo.setObjectName("lbl_dsgvo_hinweis")
            dsgvo.setWordWrap(True)
            dsgvo.setTextFormat(Qt.TextFormat.PlainText)
            dsgvo.setStyleSheet(
                f"color: {theme.DARK_BG_PRIMARY}; "
                f"background-color: {theme.WARNING_ORANGE}; "
                "padding: 8px 10px; border-radius: 6px; font-weight: 600;"
            )
            root.addWidget(dsgvo)

        # Inline-Fehlerzeile (Pflichtfeld-Validierung).
        self._error_label = QLabel("")
        self._error_label.setObjectName("lbl_phase_error")
        self._error_label.setWordWrap(True)
        self._error_label.setTextFormat(Qt.TextFormat.PlainText)
        self._error_label.setStyleSheet(
            f"color: {theme.DARK_DANGER}; font-weight: 600;"
        )
        self._error_label.setVisible(False)
        root.addWidget(self._error_label)

        # Aktionen: Entwurf speichern / Phase einreichen / Schliessen.
        buttons = QDialogButtonBox()
        self._save_btn = QPushButton("Entwurf speichern")
        self._save_btn.setObjectName("btn_save_draft")
        self._save_btn.clicked.connect(self._on_save_draft)
        buttons.addButton(
            self._save_btn, QDialogButtonBox.ButtonRole.ActionRole
        )
        self._submit_btn = QPushButton("Phase einreichen")
        self._submit_btn.setObjectName("btn_submit_phase")
        self._submit_btn.setProperty("class", "primary")
        self._submit_btn.clicked.connect(self._on_submit)
        buttons.addButton(
            self._submit_btn, QDialogButtonBox.ButtonRole.AcceptRole
        )
        cancel_btn = buttons.addButton(
            QDialogButtonBox.StandardButton.Cancel
        )
        cancel_btn.setText("Schliessen")
        cancel_btn.clicked.connect(self.reject)
        root.addWidget(buttons)

    def _build_field_block(self, field: FormField) -> QWidget:
        """Baut Label + Hilfetext + Eingabe-Widget fuer EIN Feld.

        Args:
            field: Das zu rendernde Schema-Feld.

        Returns:
            Container-Widget mit Beschriftung, sichtbarem Hilfetext und
            (bei Freitext) PII-Hinweis.
        """
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)

        label_text = field.label + (" *" if field.required else "")
        label = QLabel(label_text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setStyleSheet(
            f"color: {theme.DARK_TEXT_PRIMARY}; font-weight: 600;"
        )
        layout.addWidget(label)

        # Sichtbarer Was-zu-tun-Hilfetext (nicht nur Tooltip).
        if field.help_text:
            help_lbl = QLabel(field.help_text)
            help_lbl.setObjectName("lbl_field_help")
            help_lbl.setWordWrap(True)
            help_lbl.setTextFormat(Qt.TextFormat.PlainText)
            help_lbl.setStyleSheet(
                f"color: {theme.DARK_TEXT_SECONDARY}; "
                f"font-size: {theme.FONT_SIZE_CAPTION}px;"
            )
            layout.addWidget(help_lbl)

        widget = self._build_input_widget(field)
        widget.setObjectName(f"field_{field.key}")
        layout.addWidget(widget)
        self._widgets[field.key] = field

        # PII-Hinweis an Freitext-/Listenfeldern §4).
        if field.typ in (FieldType.TEXT, FieldType.MULTILINE, FieldType.LIST):
            pii = QLabel(PII_HINWEIS)
            pii.setObjectName("lbl_pii_hinweis")
            pii.setWordWrap(True)
            pii.setTextFormat(Qt.TextFormat.PlainText)
            pii.setStyleSheet(
                f"color: {theme.WARNING_ORANGE}; "
                f"font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-style: italic;"
            )
            layout.addWidget(pii)

        return block

    def _build_input_widget(self, field: FormField) -> QWidget:
        """Erzeugt das FieldType-spezifische Eingabe-Widget + registriert Getter.

        Args:
            field: Das Schema-Feld.

        Returns:
            Das Eingabe-Widget (Getter wird in ``self._getters`` hinterlegt).
        """
        typ = field.typ
        if typ is FieldType.TEXT:
            w = QLineEdit()
            self._getters[field.key] = lambda w=w: w.text().strip()
        elif typ is FieldType.MULTILINE:
            w = QPlainTextEdit()
            w.setFixedHeight(70)
            self._getters[field.key] = (
                lambda w=w: w.toPlainText().strip()
            )
        elif typ is FieldType.BOOL:
            w = QCheckBox("Ja")
            self._getters[field.key] = lambda w=w: w.isChecked()
        elif typ is FieldType.TRISTATE:
            w = QComboBox()
            for value, label in _TRISTATE_OPTIONS:
                w.addItem(label, userData=value)
            self._getters[field.key] = (
                lambda w=w: str(w.currentData() or "")
            )
        elif typ is FieldType.NUMBER:
            w = QSpinBox()
            w.setRange(0, 1_000_000_000)
            self._getters[field.key] = lambda w=w: w.value()
        elif typ is FieldType.LIST:
            w = QPlainTextEdit()
            w.setFixedHeight(70)
            w.setPlaceholderText("Ein Eintrag pro Zeile")
            self._getters[field.key] = lambda w=w: _lines(w.toPlainText())
        elif typ is FieldType.DATETIME:
            w = QDateTimeEdit()
            w.setTimeZone(QTimeZone(QTimeZone.UTC))
            w.setDateTime(QDateTime.currentDateTimeUtc())
            w.setCalendarPopup(True)
            w.setDisplayFormat("yyyy-MM-dd HH:mm 'UTC'")
            self._getters[field.key] = lambda w=w: _qdt_to_iso(w)
        else:  # pragma: no cover - alle FieldType abgedeckt
            w = QLineEdit()
            self._getters[field.key] = lambda w=w: w.text().strip()
        return w

    # ------------------------------------------------------------------
    # Draft laden / Payload sammeln
    # ------------------------------------------------------------------

    def _load_existing_draft(self) -> None:
        """Laedt einen bestehenden Draft und befuellt die Widgets.

        Fail-soft: bei Lese-/Mapping-Fehlern bleibt das Formular leer und der
        Dialog oeffnet sich trotzdem (Tool darf nie crashen).
        """
        try:
            draft = self._service.load_draft(self._incident_id, self._phase)
        except (RuntimeError, OSError):
            _log.exception("nis2_phase_draft_load_failed")
            return
        if not draft:
            return
        for field in self._fields:
            if field.key in draft:
                self._apply_value(field, draft[field.key])

    def _apply_value(self, field: FormField, value: object) -> None:
        """Setzt einen geladenen Draft-Wert in das passende Widget."""
        w = self.findChild(QWidget, f"field_{field.key}")
        if w is None:
            return
        typ = field.typ
        if typ is FieldType.TEXT and isinstance(w, QLineEdit):
            w.setText(str(value or ""))
        elif typ is FieldType.MULTILINE and isinstance(w, QPlainTextEdit):
            w.setPlainText(str(value or ""))
        elif typ is FieldType.BOOL and isinstance(w, QCheckBox):
            w.setChecked(bool(value))
        elif typ is FieldType.TRISTATE and isinstance(w, QComboBox):
            idx = w.findData(str(value or ""))
            w.setCurrentIndex(idx if idx >= 0 else 0)
        elif typ is FieldType.NUMBER and isinstance(w, QSpinBox):
            try:
                w.setValue(int(value))
            except (TypeError, ValueError):
                w.setValue(0)
        elif typ is FieldType.LIST and isinstance(w, QPlainTextEdit):
            if isinstance(value, (list, tuple)):
                w.setPlainText("\n".join(str(v) for v in value))
            else:
                w.setPlainText(str(value or ""))
        elif typ is FieldType.DATETIME and isinstance(w, QDateTimeEdit):
            qdt = QDateTime.fromString(str(value or ""), Qt.DateFormat.ISODate)
            if qdt.isValid():
                qdt.setTimeZone(QTimeZone(QTimeZone.UTC))
                w.setDateTime(qdt)

    def _gather_payload(self) -> dict:
        """Liest den aktuellen Formular-Stand als Payload-Dict aus."""
        return {key: getter() for key, getter in self._getters.items()}

    # ------------------------------------------------------------------
    # Aktionen
    # ------------------------------------------------------------------

    def _on_save_draft(self) -> None:
        """Speichert den aktuellen Payload als mutablen Draft (keine Pflichtpruefung)."""
        payload = self._gather_payload()
        try:
            self._service.save_draft(self._incident_id, self._phase, payload)
        except (RuntimeError, OSError) as exc:
            self._show_error(f"Entwurf speichern fehlgeschlagen: {exc}")
            return
        self._sync_personenbezug(payload)
        self._result_payload = payload
        self._action = self.ACTION_SAVED
        self.accept()

    def _on_submit(self) -> None:
        """Validiert Pflichtfelder und reicht die Phase ein (Append-only-Event)."""
        payload = self._gather_payload()
        missing = nis2_phase_schema.validate(self._phase, payload)
        if missing:
            labels = [
                f.label for f in self._fields if f.key in set(missing)
            ]
            self._show_error(
                "Bitte fuellen Sie die Pflichtfelder aus: "
                + ", ".join(labels)
                + "."
            )
            return
        try:
            # Draft speichern, damit submit_draft den vollstaendigen Payload
            # aus der Draft-Tabelle in das Append-only-Event uebernimmt.
            self._service.save_draft(self._incident_id, self._phase, payload)
            self._service.submit_draft(
                self._incident_id, self._phase, status=PhaseStatus.DONE
            )
            # submit_draft schreibt nur das Event (Append-only-Trennung) —
            # den Header auf die naechste Phase schaltet der Service separat,
            # ohne ein zweites Event zu erzeugen §2).
            self._service.advance_header_after_submit(
                self._incident_id, self._phase
            )
        except ValueError as exc:
            self._show_error(str(exc))
            return
        except (RuntimeError, OSError) as exc:
            self._show_error(f"Einreichen fehlgeschlagen: {exc}")
            return
        self._sync_personenbezug(payload)
        self._result_payload = payload
        self._action = self.ACTION_SUBMIT
        self.accept()

    def _sync_personenbezug(self, payload: dict) -> None:
        """Synchronisiert das Header-Flag mit dem NOTIFICATION-Payload §4).

        Nur in der NOTIFICATION-Phase und nur, wenn ein ``personenbezug``-Feld
        existiert. Fail-soft: ein Fehler beim Header-Update darf den bereits
        gespeicherten Entwurf/das Event nicht zuruecknehmen.
        """
        if self._phase is not IncidentPhase.NOTIFICATION:
            return
        if "personenbezug" not in payload:
            return
        try:
            self._service.set_personenbezug(
                self._incident_id, bool(payload["personenbezug"])
            )
        except (RuntimeError, OSError):
            _log.exception("nis2_personenbezug_sync_failed")

    def _show_error(self, message: str) -> None:
        """Zeigt eine Inline-Fehlermeldung (ohne den Dialog zu schliessen)."""
        if self._error_label is not None:
            self._error_label.setText(message)
            self._error_label.setVisible(True)

    # ------------------------------------------------------------------
    # Ergebnis-Zugriff
    # ------------------------------------------------------------------

    def chosen_action(self) -> str:
        """Liefert die gewaehlte Aktion (``ACTION_*``)."""
        return self._action

    def collected_payload(self) -> dict:
        """Liefert den zuletzt gespeicherten/eingereichten Payload."""
        return dict(self._result_payload)


# ----------------------------------------------------------------------
# Modul-Helfer (GUI-frei testbar)
# ----------------------------------------------------------------------


def _phase_title(phase: IncidentPhase) -> str:
    """Pure: kurzer Anzeigetitel einer Phase."""
    titles = {
        IncidentPhase.DETECT: "Detect",
        IncidentPhase.TRIAGE: "Triage",
        IncidentPhase.EARLY_WARNING: "24h Fruehwarnung",
        IncidentPhase.NOTIFICATION: "72h Meldung",
        IncidentPhase.FINAL_REPORT: "30d Abschlussbericht",
        IncidentPhase.POST_INCIDENT: "Post-Incident",
    }
    return titles.get(phase, phase.value)


def _lines(text: str) -> list[str]:
    """Pure: zerlegt mehrzeiligen Text in eine Liste nicht-leerer Zeilen."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def _qdt_to_iso(widget: QDateTimeEdit) -> str:
    """Liest ein QDateTimeEdit als ISO-UTC-String (aware).

    Args:
        widget: Das UTC-gefuehrte Datetime-Widget.

    Returns:
        ISO-8601-String in UTC (z. B. ``2026-06-22T08:00:00+00:00``).
    """
    dt = widget.dateTime().toUTC().toPython().replace(tzinfo=UTC)
    return dt.isoformat()
