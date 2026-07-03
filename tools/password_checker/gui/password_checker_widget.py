"""password_checker_widget — GUI für den Passwort-Policy-Checker.

Benutzer gibt ein Passwort ein, wählt eine Policy und erhält eine
Stärke-Bewertung, Policy-Compliance-Check und optionalen HIBP-Breach-Check.

Security:
    - Das Passwort wird niemals geloggt oder persistiert.
    - HIBP-Check läuft in QThread (UI blockiert nicht).
    - Passwort wird nach Anzeige nicht zwischengespeichert.

Schichtzugehörigkeit: gui/ — keine Geschäftslogik, nur UI.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import secrets
import string

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSlider,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton
from core.icons import Icons, get_icon
from core.widgets.empty_state import EmptyState
from core.widgets.tool_page import ToolPage
from tools.password_checker.application.password_service import PasswordService
from tools.password_checker.domain.models import (
    PasswordCheckResult,
    PasswordStaerke,
)
from tools.password_checker.domain.policy_templates import VORLAGE_NAMEN

# ---------------------------------------------------------------------------
# Farb-Konstanten (Severity-unabhängig vom Theme)
# ---------------------------------------------------------------------------

_STAERKE_FARBEN: dict[PasswordStaerke, str] = {
    PasswordStaerke.SEHR_SCHWACH: theme.SEVERITY_SIGNAL_CRITICAL,
    PasswordStaerke.SCHWACH: theme.SEVERITY_SIGNAL_HIGH,
    PasswordStaerke.MITTEL: theme.SEVERITY_SIGNAL_MEDIUM,
    PasswordStaerke.STARK: theme.SEVERITY_SIGNAL_OK,
    PasswordStaerke.SEHR_STARK: theme.SEVERITY_SIGNAL_OK,
}

_STAERKE_LABEL: dict[PasswordStaerke, str] = {
    PasswordStaerke.SEHR_SCHWACH: "SEHR SCHWACH",
    PasswordStaerke.SCHWACH: "SCHWACH",
    PasswordStaerke.MITTEL: "MITTEL",
    PasswordStaerke.STARK: "STARK",
    PasswordStaerke.SEHR_STARK: "SEHR STARK",
}


# ---------------------------------------------------------------------------
# Worker-Thread für HIBP-Check
# ---------------------------------------------------------------------------


class _HibpWorker(QObject):
    """Führt den HIBP-Breach-Check im Hintergrund aus."""

    fertig = Signal(bool, int)  # (kompromittiert, anzahl)
    fehler = Signal(str)

    def __init__(self, service: PasswordService, passwort: str) -> None:
        super().__init__()
        self._service = service
        self._passwort = passwort

    @Slot()
    def run(self) -> None:
        """Führt die HIBP-Prüfung aus."""
        try:
            result = self._service.pruefen(
                self._passwort,
                mit_breach_check=True,
            )
            kompromittiert = result.ist_kompromittiert
            vorkommnisse = result.breach_vorkommnisse
            self.fertig.emit(kompromittiert, max(0, vorkommnisse))
        except Exception as exc:
            self.fehler.emit(str(exc))


# ---------------------------------------------------------------------------
# Haupt-Widget
# ---------------------------------------------------------------------------


class PasswordCheckerWidget(QWidget):
    """Haupt-Widget des Passwort-Policy-Checkers."""

    def __init__(
        self,
        service: PasswordService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._thread: QThread | None = None
        self._worker: _HibpWorker | None = None
        self._letztes_passwort: str = ""
        self._build_ui()
        theme.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        """Erstellt die gesamte Oberfläche."""
        # Kopf (Titel + Akzentlinie + HelpPanel) via ToolPage AP7).
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        page = ToolPage("Passwort-Policy-Checker", help_key="password_checker")
        root.addWidget(page)

        # 2-Spalten-Split AP5b, Muster R5): Eingabe+Generator links
        # in fester Spaltenbreite, Ergebnis rechts als Primärfläche mit
        # stretch=1 — statt Formularstapel oben + addStretch-Leere darunter.
        cols = QHBoxLayout()
        cols.setSpacing(20)

        left_col = QWidget()
        left_lyt = QVBoxLayout(left_col)
        left_lyt.setContentsMargins(0, 0, 0, 0)
        left_lyt.setSpacing(16)
        left_col.setMaximumWidth(520)
        left_lyt.addWidget(self._build_eingabe_panel())
        # addStretch ist hier legitim: innerhalb der schmalen Spalte (R1-Ausnahme)
        left_lyt.addStretch()
        cols.addWidget(left_col)

        # Rechts: Empty-State ↔ Ergebnis (scrollbar) — Muster R3.
        # Wert-erklärender Text + Beispiel-CTA: macht den Nutzen des
        # Tabs sofort verständlich, statt nur „Noch keine Prüfung".
        self._ergebnis_empty_lbl = EmptyState(
            "Noch keine Prüfung.\n\n"
            "Der Passwort-Checker bewertet Stärke und Entropie, prüft die "
            "Erfüllung deiner Policy, erkennt schwache Muster und gleicht das "
            "Passwort lokal (k-Anonymität) gegen bekannte Datenpannen ab "
            "(HIBP) — ohne es zu speichern oder im Klartext zu übertragen.\n\n"
            "Gib links ein Passwort ein und klicke „Passwort prüfen“ — oder "
            "sieh dir ein Beispiel an.",
            cta_text="Beispiel ansehen",
        )
        self._ergebnis_empty_lbl.cta_clicked.connect(self._on_beispiel)

        ergebnis_scroll = QScrollArea()
        ergebnis_scroll.setWidgetResizable(True)
        ergebnis_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        ergebnis_scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )
        self._ergebnis_panel = self._build_ergebnis_panel()
        ergebnis_scroll.setWidget(self._ergebnis_panel)

        self._ergebnis_stack = QStackedWidget()
        self._ergebnis_stack.addWidget(self._ergebnis_empty_lbl)  # Index 0
        self._ergebnis_stack.addWidget(ergebnis_scroll)  # Index 1
        cols.addWidget(self._ergebnis_stack, stretch=1)

        page.body.addLayout(cols, stretch=1)

    def _build_eingabe_panel(self) -> QWidget:
        """Erstellt das Eingabe-Panel mit Passwortfeld und Policy-Auswahl."""
        c = theme.get()
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        _field_style = (
            f"QLineEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 6px 10px;"
            f" font-family: 'Raleway'; font-size: 13px; }}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
        )
        _btn_style = (
            f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 6px 16px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )

        # Passwort-Eingabezeile
        pw_row = QHBoxLayout()
        pw_label = QLabel("Passwort:")
        pw_label.setFixedWidth(90)
        pw_label.setStyleSheet(f"color: {c.TEXT_MAIN}; font-family: 'Raleway';")
        pw_row.addWidget(pw_label)

        self._pw_input = QLineEdit()
        self._pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_input.setPlaceholderText("Passwort eingeben …")
        self._pw_input.setFixedHeight(36)
        self._pw_input.setStyleSheet(_field_style)
        self._pw_input.textChanged.connect(self._on_pw_changed)
        self._pw_input.returnPressed.connect(self._on_pruefen)
        pw_row.addWidget(self._pw_input, stretch=1)

        self._btn_anzeigen = QPushButton("")
        self._btn_anzeigen.setIcon(get_icon(Icons.LOCK_OPEN))
        self._btn_anzeigen.setFixedSize(36, 36)
        self._btn_anzeigen.setCheckable(True)
        self._btn_anzeigen.setToolTip("Passwort anzeigen/verbergen")
        self._btn_anzeigen.setStyleSheet(_btn_style)
        self._btn_anzeigen.toggled.connect(self._on_anzeigen_toggled)
        pw_row.addWidget(self._btn_anzeigen)

        _tip_pw = self._help_tip("input_password")
        if _tip_pw:
            pw_row.addWidget(HelpButton(_tip_pw))
        layout.addLayout(pw_row)

        # Policy-Auswahl
        policy_row = QHBoxLayout()
        policy_label = QLabel("Policy:")
        policy_label.setFixedWidth(90)
        policy_label.setStyleSheet(f"color: {c.TEXT_MAIN}; font-family: 'Raleway';")
        policy_row.addWidget(policy_label)

        self._policy_combo = QComboBox()
        self._policy_combo.addItems(VORLAGE_NAMEN)
        self._policy_combo.setFixedHeight(36)
        self._policy_combo.setStyleSheet(
            f"QComboBox {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
            f"QComboBox::drop-down {{ border: none; }}"
            f"QComboBox QAbstractItemView {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" selection-background-color: {c.ACCENT}; selection-color: {c.BG_DARK}; }}"
        )
        policy_row.addWidget(self._policy_combo, stretch=1)
        layout.addLayout(policy_row)

        # HIBP-Checkbox
        self._hibp_cb = QCheckBox("HIBP Breach-Check (Netzwerk erforderlich)")
        self._hibp_cb.setChecked(True)
        self._hibp_cb.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        layout.addWidget(self._hibp_cb)

        # Prüfen-Button
        self._btn_pruefen = QPushButton("Passwort prüfen")
        self._btn_pruefen.setIcon(get_icon(Icons.SEARCH))
        self._btn_pruefen.setFixedHeight(38)
        self._btn_pruefen.setEnabled(False)
        self._btn_pruefen.setStyleSheet(
            f"QPushButton {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" font-weight: bold; border: none; border-radius: 4px; padding: 6px 20px; }}"
            f"QPushButton:hover {{ background: {c.ACCENT_DARK}; }}"
            f"QPushButton:pressed {{ background: {c.ACCENT_DARK};"
            f" padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )
        self._btn_pruefen.clicked.connect(self._on_pruefen)
        layout.addWidget(self._btn_pruefen)

        # ------------------------------------------------------------------
        # Passwortgenerator
        # ------------------------------------------------------------------
        gen_sep = QFrame()
        gen_sep.setFrameShape(QFrame.Shape.HLine)
        gen_sep.setFixedHeight(1)
        gen_sep.setStyleSheet(f"background-color: {c.BORDER}; margin: 8px 0 4px 0;")
        layout.addWidget(gen_sep)

        gen_titel = QLabel("Passwortgenerator")
        gen_titel.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
        )
        layout.addWidget(gen_titel)

        # Länge-Slider
        laenge_row = QHBoxLayout()
        lbl_laenge = QLabel("Länge:")
        lbl_laenge.setFixedWidth(90)
        lbl_laenge.setStyleSheet(f"color: {c.TEXT_MAIN}; font-family: 'Raleway';")
        laenge_row.addWidget(lbl_laenge)

        self._slider_laenge = QSlider(Qt.Orientation.Horizontal)
        self._slider_laenge.setRange(8, 32)
        self._slider_laenge.setValue(16)
        self._slider_laenge.setStyleSheet(
            f"QSlider::groove:horizontal {{ background: {c.BORDER}; height: 4px;"
            f" border-radius: 2px; }}"
            f"QSlider::handle:horizontal {{ background: {c.ACCENT}; width: 14px;"
            f" height: 14px; margin: -5px 0; border-radius: 7px; }}"
            f"QSlider::sub-page:horizontal {{ background: {c.ACCENT}; border-radius: 2px; }}"
        )
        laenge_row.addWidget(self._slider_laenge, stretch=1)

        self._lbl_laenge_wert = QLabel("16")
        self._lbl_laenge_wert.setFixedWidth(30)
        self._lbl_laenge_wert.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._lbl_laenge_wert.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-weight: bold;"
        )
        self._slider_laenge.valueChanged.connect(
            lambda v: self._lbl_laenge_wert.setText(str(v))
        )
        laenge_row.addWidget(self._lbl_laenge_wert)
        layout.addLayout(laenge_row)

        # Zeichenkategorien
        cb_row = QHBoxLayout()
        _cb_style = (
            f"QCheckBox {{ color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 12px; }}"
            f"QCheckBox::indicator {{ width: 16px; height: 16px;"
            f" border: 2px solid {c.BORDER}; border-radius: 3px;"
            f" background-color: {c.BG_INPUT}; }}"
            f"QCheckBox::indicator:checked {{ background-color: {c.ACCENT};"
            f" border-color: {c.ACCENT}; }}"
            f"QCheckBox::indicator:hover {{ border-color: {c.ACCENT}; }}"
        )
        self._cb_gross = QCheckBox("A–Z")
        self._cb_klein = QCheckBox("a–z")
        self._cb_zahlen = QCheckBox("0–9")
        self._cb_sonder = QCheckBox("#@!…")
        for cb in (self._cb_gross, self._cb_klein, self._cb_zahlen, self._cb_sonder):
            cb.setChecked(True)
            cb.setStyleSheet(_cb_style)
            cb_row.addWidget(cb)
        cb_row.addStretch()
        layout.addLayout(cb_row)

        # Ausgabefeld + Buttons
        gen_pw_row = QHBoxLayout()
        self._gen_pw_output = QLineEdit()
        self._gen_pw_output.setReadOnly(True)
        self._gen_pw_output.setFixedHeight(36)
        self._gen_pw_output.setPlaceholderText("— Passwort generieren —")
        self._gen_pw_output.setStyleSheet(
            f"QLineEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 6px 10px;"
            f" font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 13px; }}"
        )
        gen_pw_row.addWidget(self._gen_pw_output, stretch=1)

        self._btn_generieren = QPushButton("")
        self._btn_generieren.setIcon(get_icon(Icons.REFRESH))
        self._btn_generieren.setFixedSize(36, 36)
        self._btn_generieren.setToolTip("Neues Passwort generieren")
        self._btn_generieren.setStyleSheet(_btn_style)
        self._btn_generieren.clicked.connect(self._on_generieren)
        gen_pw_row.addWidget(self._btn_generieren)

        self._btn_gen_kopieren = QPushButton("")
        self._btn_gen_kopieren.setIcon(get_icon(Icons.COPY))
        self._btn_gen_kopieren.setFixedSize(36, 36)
        self._btn_gen_kopieren.setToolTip("In Zwischenablage kopieren")
        self._btn_gen_kopieren.setEnabled(False)
        self._btn_gen_kopieren.setStyleSheet(_btn_style)
        self._btn_gen_kopieren.clicked.connect(self._on_gen_kopieren)
        gen_pw_row.addWidget(self._btn_gen_kopieren)

        self._btn_uebernehmen = QPushButton("Prüfen")
        self._btn_uebernehmen.setIcon(get_icon(Icons.CHEVRON_RIGHT))
        self._btn_uebernehmen.setFixedHeight(36)
        self._btn_uebernehmen.setToolTip(
            "Generiertes Passwort in das Prüffeld übernehmen"
        )
        self._btn_uebernehmen.setEnabled(False)
        self._btn_uebernehmen.setStyleSheet(_btn_style)
        self._btn_uebernehmen.clicked.connect(self._on_gen_uebernehmen)
        gen_pw_row.addWidget(self._btn_uebernehmen)
        layout.addLayout(gen_pw_row)

        return panel

    def _build_ergebnis_panel(self) -> QWidget:
        """Erstellt das Ergebnis-Panel (startet hinter dem Empty-State
        des Ergebnis-Stacks AP5b)."""
        c = theme.get()
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Trennlinie
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {c.BORDER}; margin: 4px 0;")
        layout.addWidget(sep)

        # Score-Anzeige
        score_row = QHBoxLayout()
        lbl_staerke_titel = QLabel("Stärke:")
        lbl_staerke_titel.setFixedWidth(90)
        lbl_staerke_titel.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway';"
        )
        score_row.addWidget(lbl_staerke_titel)

        self._progress_staerke = QProgressBar()
        self._progress_staerke.setFixedHeight(18)
        self._progress_staerke.setTextVisible(False)
        self._progress_staerke.setRange(0, 100)
        score_row.addWidget(self._progress_staerke, stretch=1)

        self._lbl_score = QLabel("—")
        self._lbl_score.setFixedWidth(120)
        self._lbl_score.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._lbl_score.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; font-weight: bold; color: {c.ACCENT};"
        )
        score_row.addWidget(self._lbl_score)

        _tip_strength = self._help_tip("result_strength")
        if _tip_strength:
            score_row.addWidget(HelpButton(_tip_strength))
        layout.addLayout(score_row)

        # Entropie-Zeile
        entropie_row = QHBoxLayout()
        lbl_ent = QLabel("Entropie:")
        lbl_ent.setFixedWidth(90)
        lbl_ent.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        entropie_row.addWidget(lbl_ent)
        self._lbl_entropie = QLabel("—")
        self._lbl_entropie.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 12px;"
        )
        self._lbl_entropie.setToolTip(
            "Informations-Entropie: ab 60 Bits = stark, ab 80 Bits = sehr stark"
        )
        entropie_row.addWidget(self._lbl_entropie, stretch=1)
        layout.addLayout(entropie_row)

        # Policy-Checks
        policy_header = QLabel("Policy-Anforderungen:")
        policy_header.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 12px; font-weight: bold;"
            f" margin-top: 4px;"
        )
        layout.addWidget(policy_header)

        self._checks_container = QWidget()
        self._checks_layout = QVBoxLayout(self._checks_container)
        self._checks_layout.setContentsMargins(8, 0, 0, 0)
        self._checks_layout.setSpacing(4)
        layout.addWidget(self._checks_container)

        # Muster-Warnungen
        self._muster_container = QWidget()
        self._muster_layout = QVBoxLayout(self._muster_container)
        self._muster_layout.setContentsMargins(8, 0, 0, 0)
        self._muster_layout.setSpacing(4)
        layout.addWidget(self._muster_container)

        # Breach-Check Ergebnis
        self._lbl_breach = QLabel("")
        self._lbl_breach.setWordWrap(True)
        self._lbl_breach.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
            f" padding: 6px 8px; border-radius: 4px;"
        )
        layout.addWidget(self._lbl_breach)

        # HIBP Lade-Indikator
        self._lbl_hibp_laden = QLabel("⏳ Breach-Datenbank wird geprüft …")
        self._lbl_hibp_laden.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-family: 'Raleway';"
        )
        self._lbl_hibp_laden.setVisible(False)
        layout.addWidget(self._lbl_hibp_laden)

        # Empfehlungen
        self._empfehlungen_container = QWidget()
        self._empf_layout = QVBoxLayout(self._empfehlungen_container)
        self._empf_layout.setContentsMargins(0, 0, 0, 0)
        self._empf_layout.setSpacing(4)
        layout.addWidget(self._empfehlungen_container)

        # Datenschutz-Hinweis
        hinweis = QLabel("Das Passwort wurde nicht gespeichert oder übertragen.")
        hinweis.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-family: 'Raleway';"
            f" font-style: italic; margin-top: 8px;"
        )
        hinweis.setWordWrap(True)
        layout.addWidget(hinweis)

        return panel

    # ------------------------------------------------------------------
    # Passwortgenerator
    # ------------------------------------------------------------------

    @Slot()
    def _on_generieren(self) -> None:
        """Generiert ein zufälliges Passwort mit den gewählten Einstellungen."""
        zeichensatz = ""
        if self._cb_gross.isChecked():
            zeichensatz += string.ascii_uppercase
        if self._cb_klein.isChecked():
            zeichensatz += string.ascii_lowercase
        if self._cb_zahlen.isChecked():
            zeichensatz += string.digits
        if self._cb_sonder.isChecked():
            zeichensatz += "!@#$%^&*()-_=+[]{}|;:,.<>?"

        if not zeichensatz:
            return

        laenge = self._slider_laenge.value()
        passwort = "".join(secrets.choice(zeichensatz) for _ in range(laenge))
        self._gen_pw_output.setText(passwort)
        self._btn_gen_kopieren.setEnabled(True)
        self._btn_uebernehmen.setEnabled(True)

    @Slot()
    def _on_gen_kopieren(self) -> None:
        """Kopiert das generierte Passwort in die Zwischenablage."""
        pw = self._gen_pw_output.text()
        if pw:
            QApplication.clipboard().setText(pw)

    @Slot()
    def _on_gen_uebernehmen(self) -> None:
        """Überträgt das generierte Passwort in das Prüffeld."""
        pw = self._gen_pw_output.text()
        if pw:
            self._pw_input.setText(pw)

    # ------------------------------------------------------------------
    # Hilfe-System
    # ------------------------------------------------------------------
    def _help_tip(self, key: str) -> str:
        """Holt einen HelpButton-Tooltip-Text aus der Registry."""
        hc = HelpRegistry.get("password_checker")
        return hc.tooltips.get(key, "") if hc else ""

    # ------------------------------------------------------------------
    def apply_theme(self) -> None:
        """Aktualisiert Farben bei Theme-Wechsel."""
        # Widget neuaufbauen ist einfacher als alle Refs zu patchen
        layout = self.layout()
        if layout is not None:
            QWidget().setLayout(layout)
        self._thread = None
        self._worker = None
        self._build_ui()

    # ------------------------------------------------------------------
    def _on_pw_changed(self, text: str) -> None:
        """Aktiviert/deaktiviert den Prüfen-Button."""
        self._btn_pruefen.setEnabled(bool(text))

    def _on_anzeigen_toggled(self, checked: bool) -> None:
        """Schaltet Passwort-Sichtbarkeit um."""
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self._pw_input.setEchoMode(mode)

    def apply_navigation(self, *, focus: str | None = None, **_kwargs) -> None:
        """Deeplink-Ziel (Cockpit-Inc-2): ``focus='check'`` fokussiert das
        Passwort-Eingabefeld."""
        if focus == "check" and getattr(self, "_pw_input", None) is not None:
            self._pw_input.setFocus()
            self._pw_input.selectAll()

    # ------------------------------------------------------------------
    def _on_pruefen(self) -> None:
        """Startet die Passwort-Prüfung."""
        passwort = self._pw_input.text()
        if not passwort:
            return

        self._letztes_passwort = passwort
        policy = self._service.lade_policy(self._policy_combo.currentText())

        # Schnelle Analyse (ohne HIBP, synchron)
        from tools.password_checker.domain.password_analyzer import (  # noqa: PLC0415
            analysiere_passwort,
        )

        result = analysiere_passwort(passwort, policy)
        self._zeige_ergebnis(result)

        # HIBP asynchron nachziehen
        if self._hibp_cb.isChecked():
            self._starte_hibp_check(passwort, policy)

    def _on_beispiel(self) -> None:
        """Zeigt die Analyse eines Beispiel-Passworts (lokal, ohne HIBP-Netzcall).

        Demonstriert den Nutzen des Tabs mit einem Klick aus dem Empty-State
        heraus: ein typisch mittelmäßiges Passwort macht Stärke-Balken,
        Policy-Checks und Empfehlungen sofort sichtbar. Kein Netzwerk, keine
        Persistenz — reine synchrone Analyse.
        """
        beispiel = "Sommer2024!"
        self._pw_input.setText(beispiel)
        policy = self._service.lade_policy(self._policy_combo.currentText())
        from tools.password_checker.domain.password_analyzer import (  # noqa: PLC0415
            analysiere_passwort,
        )

        result = analysiere_passwort(beispiel, policy)
        self._zeige_ergebnis(result)

    def _starte_hibp_check(self, passwort: str, policy) -> None:
        """Startet den HIBP-Check im Background-Thread."""
        self._lbl_hibp_laden.setVisible(True)
        self._lbl_breach.setVisible(False)

        self._thread = QThread(self)
        self._worker = _HibpWorker(self._service, passwort)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.fertig.connect(self._on_hibp_fertig)
        self._worker.fehler.connect(self._on_hibp_fehler)
        self._worker.fertig.connect(self._thread.quit)
        self._worker.fehler.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start()

    @Slot(bool, int)
    def _on_hibp_fertig(self, kompromittiert: bool, anzahl: int) -> None:
        """Zeigt das HIBP-Ergebnis an.

        Verwirft Ergebnisse eines abgelösten Workers-F2): klickt der User
        „Prüfen" erneut, während ein Check läuft, dürfte ein spät eintreffendes
        Alt-Ergebnis sonst die Stärke-Anzeige des NEUEN Passworts überschreiben
        (z. B. ein geleaktes Passwort fälschlich „KOMPROMITTIERT" oder umgekehrt
        grün lassen). ``self.sender`` ist nur beim aktuellen Worker ``is
        self._worker``; bei Direktaufruf (Tests, kein Signal) ist beides ``None``.
        """
        if self.sender() is not self._worker:
            return
        self._lbl_hibp_laden.setVisible(False)
        self._lbl_breach.setVisible(True)

        if kompromittiert:
            # F2: Ein Breach-Treffer kappt die Stärke hart — die synchrone
            # Voranzeige (score-basiert) hätte ein entropie-„starkes", aber
            # geleaktes Passwort sonst weiter grün/„STARK" gezeigt.
            self._render_staerke(
                PasswordStaerke.SEHR_SCHWACH, 0, label_override="KOMPROMITTIERT"
            )
            self._lbl_breach.setStyleSheet(
                f"background: {theme.BG_PANEL_ERROR}; color: {theme.SEVERITY_SIGNAL_CRITICAL};"
                f" border: 1px solid {theme.SEVERITY_SIGNAL_CRITICAL};"
                " padding: 6px 8px; border-radius: 4px; font-family: 'Raleway'; font-size: 12px;"
            )
            self._lbl_breach.setText(
                f"[WARN] Passwort in {anzahl:,} Datenpannen gefunden — sofort ändern!"
            )
        else:
            self._lbl_breach.setStyleSheet(
                f"background: {theme.BG_PANEL_SUCCESS}; color: {theme.SEVERITY_SIGNAL_OK};"
                f" border: 1px solid {theme.SEVERITY_SIGNAL_OK};"
                " padding: 6px 8px; border-radius: 4px; font-family: 'Raleway'; font-size: 12px;"
            )
            self._lbl_breach.setText("Nicht in bekannten Datenpannen gefunden (HIBP)")

    @Slot(str)
    def _on_hibp_fehler(self, msg: str) -> None:
        """Zeigt HIBP-Fehler an (Ergebnisse abgelöster Worker werden verworfen)."""
        if self.sender() is not self._worker:
            return
        self._lbl_hibp_laden.setVisible(False)
        self._lbl_breach.setVisible(True)
        self._lbl_breach.setStyleSheet(
            f"color: {theme.SEVERITY_SIGNAL_INFO}; font-size: 11px; font-family: 'Raleway';"
        )
        self._lbl_breach.setText("ℹ️  Breach-Check nicht verfügbar (Netzwerkfehler)")

    # ------------------------------------------------------------------
    def _render_staerke(
        self,
        staerke: PasswordStaerke,
        score: int,
        label_override: str | None = None,
    ) -> None:
        """Rendert Stärke-Balken + Score-Label (Farbe nach Stufe).

        Ausgelagert aus:meth:`_zeige_ergebnis`, damit der asynchrone HIBP-Pfad
        (:meth:`_on_hibp_fertig`) die Anzeige bei einem Breach-Treffer auf
        „KOMPROMITTIERT" überschreiben kann-F2) — sonst bliebe der grüne
        Stärke-Balken aus der synchronen Voranzeige sichtbar.

        Args:
            staerke: Anzuzeigende Stärke-Stufe (bestimmt die Farbe).
            score: Numerischer Score 0–100 (Balken-Füllung).
            label_override: Optionaler Text statt des Standard-Stufen-Labels.
        """
        c = theme.get()
        farbe = _STAERKE_FARBEN.get(staerke, c.ACCENT)
        label = label_override or _STAERKE_LABEL.get(staerke, "—")

        self._progress_staerke.setValue(score)
        self._progress_staerke.setStyleSheet(
            f"QProgressBar {{ border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" background: {c.BG_INPUT}; }}"
            f"QProgressBar::chunk {{ background: {farbe}; border-radius: 4px; }}"
        )
        self._lbl_score.setText(f"{score}/100  —  {label}")
        self._lbl_score.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 12px; font-weight: bold; color: {farbe};"
        )

    def _zeige_ergebnis(self, result: PasswordCheckResult) -> None:
        """Füllt das Ergebnis-Panel mit den Analyse-Daten."""
        c = theme.get()
        # Score-Bar (HIBP noch nicht bekannt — der async Pfad kappt ggf. nach).
        self._render_staerke(result.staerke, result.score)

        # Entropie
        self._lbl_entropie.setText(
            f"{result.entropie_bits:.1f} Bits  ({result.laenge} Zeichen)"
        )

        # Policy-Checks
        self._clear_layout(self._checks_layout)
        for check in result.policy_checks:
            icon = "OK" if check.erfuellt else "FAIL"
            zeile = QLabel(f"{icon}  {check.bezeichnung}")
            zeile.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 12px;"
                f" color: {theme.SEVERITY_SIGNAL_OK if check.erfuellt else theme.SEVERITY_SIGNAL_CRITICAL};"
            )
            if check.hinweis:
                zeile.setToolTip(check.hinweis)
            self._checks_layout.addWidget(zeile)

        # Muster-Warnungen
        self._clear_layout(self._muster_layout)
        for muster in result.muster_gefunden:
            zeile = QLabel(f"[WARN] {muster}")
            zeile.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 12px;"
                f" color: {theme.SEVERITY_SIGNAL_HIGH};"
            )
            zeile.setWordWrap(True)
            self._muster_layout.addWidget(zeile)

        # Empfehlungen
        self._clear_layout(self._empf_layout)
        if result.empfehlungen:
            hdr = QLabel("Empfehlungen:")
            hdr.setStyleSheet(
                f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: 12px;"
                f" font-weight: bold; margin-top: 4px;"
            )
            self._empf_layout.addWidget(hdr)
            for empf in result.empfehlungen:
                zeile = QLabel(f"•  {empf}")
                zeile.setStyleSheet(
                    f"font-family: 'Raleway'; font-size: 12px; color: {c.TEXT_MAIN};"
                    f" padding-left: 8px;"
                )
                zeile.setWordWrap(True)
                self._empf_layout.addWidget(zeile)

        # Breach-Label zurücksetzen (HIBP-Check folgt asynchron)
        self._lbl_breach.setVisible(False)
        self._lbl_hibp_laden.setVisible(False)
        # Empty-State → Ergebnis umschalten AP5b)
        self._ergebnis_stack.setCurrentIndex(1)

    @staticmethod
    def _clear_layout(layout) -> None:
        """Entfernt alle Widgets aus einem Layout."""
        while layout.count():
            item = layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
