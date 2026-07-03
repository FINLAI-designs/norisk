"""W1-Interview-Seite — Profil des eigenen Systems fürs Sidebar-Gating.

Erfasst beim First-Run das **Segment** und einige objektive Infrastruktur-
Eigenschaften des eigenen Systems (eigene Website/API, eigene Entwicklung,
Server/NAS). Daraus leitet die Sidebar das **Profil-Gating** ab (Phase 3d,
): profil-irrelevante Module (z. B. „API-Security" ohne eigene API)
werden ausgegraut — reversibel über die Einstellungen.

Vorbild ist:class:`core.first_run_wizard.pages.scoping_page.CompanyScopingPage`:
alle Felder optional (nie ein „Gate", ``is_complete`` bleibt True), Persistenz
fail-soft (fehlt der ``SubjectStore``, werden die Angaben verworfen statt den
Wizard abzubrechen).

Tri-state-Semantik je Eigenschaft (0/1/None):
    „Ja" → ``1`` (vorhanden),
    „Nein" → ``0`` (fehlt → Modul wird gegatet),
    „keine Angabe"→ unverändert lassen (Sentinel) — kein Gating, kein Überschreiben.

M365 wird hier bewusst NICHT erfasst: es lebt tri-state in
:class:`core.security_subject.models.NutzungsSignale` (aus SELF-Audits abgeleitet,
) und treibt das Scoring, nicht das Gating — eine zweite Erfassung hier
wäre eine zweite Wahrheit.

Schichtzugehörigkeit: core/ — nutzt den core-Resolver, keinen tools-Import.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLabel,
    QWidget,
)

from core.audit_log import AuditLogger
from core.first_run_wizard.pages.base_page import BasePage
from core.logger import get_logger
from core.security_subject.resolver import create_subject_store
from core.security_subject.w1_profil import SEGMENTE, W1_UNCHANGED
from core.theme import (
    ACCENT_HOVER,
    BG_PANEL_DARK,
    DARK_ACCENT,
    DARK_BORDER,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
)

log = get_logger(__name__)

_PLATZHALTER = "— bitte wählen —"
_KEINE_ANGABE = "keine Angabe"


class W1ProfilePage(BasePage):
    """Optionale W1-Erfassung des eigenen System-Profils fürs Gating."""

    TITLE = "Dein System"

    def __init__(self) -> None:
        super().__init__()

        title = QLabel("Dein System")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 20px; font-weight: bold;"
            f" color: {DARK_ACCENT};"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(
            "Diese Angaben blenden Module aus, die für dich nicht relevant sind "
            "(z. B. API-Security ohne eigene API). Alle Felder sind freiwillig — "
            "Du kannst später in den Einstellungen alles wieder einblenden."
        )
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_SECONDARY};"
        )

        self._segment = QComboBox()
        self._segment.addItem(_PLATZHALTER, "")
        for key, label in SEGMENTE:
            self._segment.addItem(label, str(key))

        self._website = self._make_tristate()
        self._api = self._make_tristate()
        self._entwickler = self._make_tristate()
        self._server = self._make_tristate()

        input_style = (
            "QComboBox {"
            f" background-color: {BG_PANEL_DARK}; border: 1px solid {DARK_BORDER};"
            f" color: {DARK_TEXT_PRIMARY}; border-radius: 6px; padding: 6px 10px;"
            " font-family: 'Raleway'; font-size: 13px;"
            f"}} QComboBox:focus {{ border: 1px solid {ACCENT_HOVER}; }}"
        )
        for widget in (
            self._segment,
            self._website,
            self._api,
            self._entwickler,
            self._server,
        ):
            widget.setStyleSheet(input_style)
            widget.setFixedHeight(36)

        form_host = QWidget()
        form = QFormLayout(form_host)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.addRow(self._label("Dein Segment"), self._segment)
        form.addRow(self._label("Eigene Website / Domain?"), self._website)
        form.addRow(self._label("Eigene öffentliche API?"), self._api)
        form.addRow(self._label("Eigene Software-Entwicklung?"), self._entwickler)
        form.addRow(self._label("Eigener Server / NAS?"), self._server)

        self._layout.addStretch(1)
        self._layout.addWidget(title)
        self._layout.addWidget(hint)
        self._layout.addSpacing(12)
        self._layout.addWidget(form_host)
        self._layout.addStretch(2)

    # ------------------------------------------------------------------
    # UI-Helfer
    # ------------------------------------------------------------------

    @staticmethod
    def _make_tristate() -> QComboBox:
        """Baut eine tri-state-Combo (keine Angabe = None, Ja = 1, Nein = 0)."""
        combo = QComboBox()
        combo.addItem(_KEINE_ANGABE, None)
        combo.addItem("Ja", 1)
        combo.addItem("Nein", 0)
        return combo

    @staticmethod
    def _label(text: str) -> QLabel:
        """Baut ein Formular-Label im Wizard-Stil."""
        label = QLabel(text)
        label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {DARK_TEXT_PRIMARY};"
        )
        return label

    @staticmethod
    def _tristate_arg(combo: QComboBox) -> int | None:
        """Übersetzt die Combo-Auswahl in das ``update_profile_w1``-Argument.

        „keine Angabe" (``currentData is None``) → Sentinel (unverändert);
        „Ja"/„Nein" → ``1``/``0``.
        """
        data = combo.currentData()
        return W1_UNCHANGED if data is None else int(data)

    # ------------------------------------------------------------------
    # Persistenz (fail-soft, optional)
    # ------------------------------------------------------------------

    def commit(self) -> None:
        """Schreibt die W1-Angaben auf das eigene Subjekt (fail-soft).

        Bricht den Wizard nie ab: ohne Angaben passiert nichts; fehlt der
        ``SubjectStore`` oder schlägt die DB fehl, werden die Angaben verworfen
        statt geworfen (Cross-App/, Vorbild scoping_page).
        """
        segment = self._segment.currentData() or ""
        website = self._tristate_arg(self._website)
        api = self._tristate_arg(self._api)
        entwickler = self._tristate_arg(self._entwickler)
        server = self._tristate_arg(self._server)

        nichts_erfasst = not segment and all(
            v == W1_UNCHANGED for v in (website, api, entwickler, server)
        )
        if nichts_erfasst:
            return  # Nichts gewählt — kein Schreibvorgang, kein Audit-Event.

        try:
            store = create_subject_store()
            if store is None:
                log.info("W1: SubjectStore nicht verfügbar — Angaben nicht gespeichert.")
                return
            subject = store.get_self()
            if subject is None:
                log.warning("W1: kein eigenes Subjekt vorhanden — Angaben verworfen.")
                return
            store.update_profile_w1(
                subject.subject_id,
                segment=segment or None,  # None = unverändert
                hat_eigene_website=website,
                hat_eigene_api=api,
                ist_entwickler=entwickler,
                hat_server_infrastruktur=server,
            )
        except Exception:  # noqa: BLE001 — optionales W1 darf den Wizard nie abbrechen
            log.warning("W1-Angaben konnten nicht gespeichert werden.")
            return

        # R8/DSGVO: nur Kategorie + Vorhandensein loggen, keine konkreten Werte.
        AuditLogger().log_action(
            "FIRST_RUN_W1_CAPTURED",
            {
                "has_segment": bool(segment),
                "website_set": website != W1_UNCHANGED,
                "api_set": api != W1_UNCHANGED,
                "entwickler_set": entwickler != W1_UNCHANGED,
                "server_set": server != W1_UNCHANGED,
            },
        )
        log.info("First-Run-W1-Profil erfasst (Segment gesetzt=%s).", bool(segment))
