"""Einstiegs-Scoping-Seite — NIS2-taugliches Profil des eigenen Systems.

Erfasst beim First-Run optionale, *objektive* Stammdaten (Rolle, Sektor nach
NIS2-Anhang, Mitarbeiterzahl, Umsatz, Bilanzsumme) und schreibt sie auf das
eigene Subjekt (``kind=EIGENES``). Diese Daten sind das Fundament für die
spätere, bedingte Sicherheitsbewertung und die NIS2-Betroffenheits-
prüfung (W0) — die UI verzweigt hier bewusst NICHT (Leitprinzip „tiefe Daten,
schlanke UI"; Entscheidung Patrick 2026-06-04).

Alle Felder sind optional: die Seite ist nie ein „Gate" (``is_complete`` bleibt
True). Die Persistenz ist fail-soft — fehlt der ``SubjectStore`` (z. B. in
Nicht-NoRisk-Apps oder ohne SQLCipher-Schlüssel), werden die Angaben verworfen,
statt den Wizard abzubrechen (Cross-App).

Abgrenzung: Firmenname/UID/Adresse für Rechnungen bleiben Sache der separaten
:class:`core.first_run_wizard.pages.company_info_page.CompanyInfoPage`
(Billing, Pro-Launch).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QSpinBox,
    QWidget,
)

from core.audit_log import AuditLogger
from core.first_run_wizard.pages.base_page import BasePage
from core.logger import get_logger
from core.security_subject.resolver import create_subject_store
from core.security_subject.scoping_constants import ROLLEN, SEKTOREN, anhang_fuer
from core.theme import (
    ACCENT_HOVER,
    BG_PANEL_DARK,
    DARK_ACCENT,
    DARK_BORDER,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
)

log = get_logger(__name__)

# Obergrenzen der Spinboxen. Umsatz/Bilanz in ganzen EUR — für die EPU/KMU-
# Zielgruppe großzügig, bleibt unter dem QSpinBox-int32-Limit.
_MAX_FTE = 1_000_000
_MAX_EUR = 2_000_000_000
_EUR_STEP = 10_000
_PLATZHALTER = "— bitte wählen —"
_KEINE_ANGABE = "keine Angabe"


class CompanyScopingPage(BasePage):
    """Optionale Einstiegs-Erfassung des eigenen Unternehmensprofils."""

    TITLE = "Dein Unternehmen"

    def __init__(self) -> None:
        super().__init__()

        title = QLabel("Dein Unternehmen")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(
            "Diese Angaben schneiden die Sicherheitsbewertung auf dein "
            "Unternehmen zu (Größe, Branche, NIS2). Alle Felder sind freiwillig "
            "— du kannst sie jederzeit später ergänzen."
        )
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {DARK_TEXT_SECONDARY};"
        )

        self._rolle = QComboBox()
        self._rolle.addItem(_PLATZHALTER, "")
        for rolle in ROLLEN:
            self._rolle.addItem(rolle, rolle)

        self._sektor = QComboBox()
        self._sektor.addItem(_PLATZHALTER, "")
        for sektor in SEKTOREN:
            self._sektor.addItem(sektor.label, sektor.key)

        self._fte = QSpinBox()
        self._fte.setRange(0, _MAX_FTE)
        self._fte.setSpecialValueText(_KEINE_ANGABE)
        self._fte.setGroupSeparatorShown(True)

        self._umsatz = self._make_euro_spin()
        self._bilanz = self._make_euro_spin()

        input_style = (
            "QComboBox, QSpinBox {"
            f" background-color: {BG_PANEL_DARK}; border: 1px solid {DARK_BORDER};"
            f" color: {DARK_TEXT_PRIMARY}; border-radius: 6px; padding: 6px 10px;"
            " font-family: 'Raleway'; font-size: 13px;"
            f"}} QComboBox:focus, QSpinBox:focus {{ border: 1px solid {ACCENT_HOVER}; }}"
        )
        for widget in (self._rolle, self._sektor, self._fte, self._umsatz, self._bilanz):
            widget.setStyleSheet(input_style)
            widget.setFixedHeight(36)

        form_host = QWidget()
        form = QFormLayout(form_host)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.addRow(self._label("Deine Rolle"), self._rolle)
        form.addRow(self._label("Branche / Sektor"), self._sektor)
        form.addRow(self._label("Mitarbeitende (Vollzeit)"), self._fte)
        form.addRow(self._label("Jahresumsatz"), self._umsatz)
        form.addRow(self._label("Bilanzsumme"), self._bilanz)

        self._layout.addStretch(1)
        self._layout.addWidget(title)
        self._layout.addWidget(hint)
        self._layout.addSpacing(12)
        self._layout.addWidget(form_host)
        self._layout.addStretch(2)

    # ------------------------------------------------------------------
    # UI-Helfer
    # ------------------------------------------------------------------

    def _make_euro_spin(self) -> QSpinBox:
        """Baut eine EUR-Spinbox (0 = keine Angabe, Tausender-Trennung)."""
        spin = QSpinBox()
        spin.setRange(0, _MAX_EUR)
        spin.setSingleStep(_EUR_STEP)
        spin.setSuffix(" €")
        spin.setSpecialValueText(_KEINE_ANGABE)
        spin.setGroupSeparatorShown(True)
        return spin

    @staticmethod
    def _label(text: str) -> QLabel:
        """Baut ein Formular-Label im Wizard-Stil."""
        label = QLabel(text)
        label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_PRIMARY};"
        )
        return label

    @staticmethod
    def _int_or_none(spin: QSpinBox) -> int | None:
        """Gibt den Spinbox-Wert zurück — oder ``None`` bei „keine Angabe" (Minimum)."""
        value = spin.value()
        return None if value == spin.minimum() else value

    # ------------------------------------------------------------------
    # Persistenz (fail-soft, optional)
    # ------------------------------------------------------------------

    def commit(self) -> None:
        """Schreibt die Scoping-Angaben auf das eigene Subjekt (fail-soft).

        Bricht den Wizard nie ab: Sind keine Angaben gemacht, passiert nichts.
        Fehlt der ``SubjectStore`` (Nicht-NoRisk-App, kein SQLCipher-Schlüssel)
        oder schlägt die DB fehl, werden die Angaben verworfen statt geworfen.
        """
        fte = self._int_or_none(self._fte)
        umsatz = self._int_or_none(self._umsatz)
        bilanz = self._int_or_none(self._bilanz)
        sektor_key = self._sektor.currentData() or ""
        rolle = self._rolle.currentData() or ""

        if not (fte or umsatz or bilanz or sektor_key or rolle):
            return  # Nichts erfasst — kein Schreibvorgang, kein Audit-Event.

        anhang = anhang_fuer(sektor_key)
        try:
            store = create_subject_store()
            if store is None:
                log.info(
                    "Scoping: SubjectStore nicht verfügbar — Angaben nicht gespeichert."
                )
                return
            subject = store.get_self()
            if subject is None:
                log.warning("Scoping: kein eigenes Subjekt vorhanden — Angaben verworfen.")
                return
            # nis2_anhang wird im Adapter aus sektor_key abgeleitet (Single Write
            # Path) — hier NICHT übergeben, damit der Wert nie desynchronisiert.
            store.update_scoping_profile(
                subject.subject_id,
                fte=fte,
                umsatz_eur=umsatz,
                bilanzsumme_eur=bilanz,
                sektor_key=sektor_key or None,
                rolle=rolle or None,
            )
        except Exception:  # noqa: BLE001 — optionales Scoping darf den Wizard nie abbrechen
            log.warning("Scoping-Angaben konnten nicht gespeichert werden.")
            return

        # DSGVO Art. 5 / R8: keine Geschäftszahlen ins Klartext-Log — nur
        # Kategorie + Vorhandensein. Der Umsatz/die Bilanz selbst nie.
        AuditLogger().log_action(
            "FIRST_RUN_SCOPING_CAPTURED",
            {
                "sektor": sektor_key,
                "anhang": anhang,
                "has_fte": fte is not None,
                "has_umsatz": umsatz is not None,
                "has_bilanz": bilanz is not None,
                "has_rolle": bool(rolle),
            },
        )
        log.info("First-Run-Scoping erfasst (Sektor=%s, Anhang=%s).", sektor_key, anhang)
