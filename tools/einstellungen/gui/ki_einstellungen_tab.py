"""ki_einstellungen_tab.py — KI-Einstellungen für NoRisk.

Zentrale Konfigurationsseite für lokale Ollama-Inferenz:
  - Provider-Anzeige (statisch: Ollama lokal — kein Cloud-Provider mehr)
  - Modell-Auswahl + Gemma-4-Empfehlung
  - Temperatur + Max-Tokens

**// (28.05.2026):** NoRisk ist 100% lokal — alle
Cloud-LLM-Provider (OpenAI, Anthropic) und das DeepL-Tool wurden
entfernt. Die frühere Multi-Provider-Auswahl + Cloud-API-Key-Felder +
DSGVO-Consent-Dialoge sind nicht mehr Teil dieser UI; Bestandsdaten in
``SecureStorage`` (alte Cloud-Keys) werden von keinem aktiven Code-Pfad
mehr gelesen — siehe SECURITY.md („LLM-Inferenz — Ollama-only, lokal").

Schichtzugehörigkeit: gui/ (darf core/, application/ importieren).

Author: Patrick Riederich
Version: 2.0-ui Rewrite, 2026-05-28)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import Icons, get_icon
from core.logger import get_logger

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

_GEMMA_EMPFEHLUNG_URL = "https://ai.google.dev/gemma"

_MAX_TOKENS_OPTIONEN: list[int] = [512, 1024, 2048, 4096, 8192]

# Provider-ID hardcoded — seit/ ist Ollama der einzige
# unterstuetzte LLM-Provider (siehe ``core/llm/llm_factory.py`` und
# ````). Wert wird beim Speichern in der LLMProviderConfig
# hinterlegt; Bestandsdaten mit Legacy-IDs ("openai" / "anthropic") fallen
# in der Factory ohnehin auf Ollama zurueck.
_PROVIDER_ID = "ollama"


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    c = theme.get()
    lbl.setStyleSheet(
        f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 11px;"
        f" font-weight: bold; text-transform: uppercase; letter-spacing: 1px;"
    )
    return lbl


def _separator() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    c = theme.get()
    line.setStyleSheet(f"color: {c.BORDER}; background: {c.BORDER}; max-height: 1px;")
    return line


def _btn_style(c, accent: bool = False) -> str:
    if accent:
        return (
            f"QPushButton {{ background: {theme.DARK_ACCENT};"
            f" color: {theme.TEXT_ON_ACCENT_DEEP}; border: none;"
            f" border-radius: 4px; font-family: 'Raleway'; font-size: 13px;"
            f" font-weight: bold; padding: 0 16px; }}"
            f"QPushButton:hover {{ background: {theme.ACCENT_HOVER}; }}"
        )
    return (
        f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
        f" border: 1px solid {c.BORDER}; border-radius: 4px;"
        f" font-family: 'Raleway'; font-size: 13px; padding: 0 12px; }}"
        f"QPushButton:hover {{ background: {c.BG_SIDEBAR_HOVER}; }}"
    )


def _combo_style(c) -> str:
    return (
        f"QComboBox {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
        f" border: 1px solid {c.BORDER}; border-radius: 4px;"
        f" font-family: 'Raleway'; font-size: 13px; padding: 0 8px; }}"
    )


# ---------------------------------------------------------------------------
# KiEinstellungenTab
# ---------------------------------------------------------------------------


class KiEinstellungenTab(QWidget):
    """KI-Einstellungen — Ollama-only.

    Erlaubt Modell-Auswahl, Temperatur und Max-Tokens fuer die lokale
    Ollama-Inferenz. Provider-Anzeige ist statisch — seit/
    sind keine Cloud-Provider mehr aktivierbar.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = self._lade_config()
        self._provider = self._lade_provider()
        self._build_ui()
        self._lade_aktuelle_werte()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)

    # ------------------------------------------------------------------
    # Initialisierung
    # ------------------------------------------------------------------

    def _lade_config(self):
        try:
            from core.llm.llm_config import LLMProviderConfig  # noqa: PLC0415

            return LLMProviderConfig()
        except (ImportError, OSError, RuntimeError):
            _log.exception("LLMProviderConfig konnte nicht geladen werden")
            return None

    def _lade_provider(self):
        try:
            from core.llm.llm_factory import LLMFactory  # noqa: PLC0415

            return LLMFactory.erstelle_ollama()
        except (ImportError, OSError, RuntimeError):
            _log.exception("OllamaProvider konnte nicht geladen werden")
            return None

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        c = theme.get()
        scroll.setStyleSheet(
            f"QScrollArea {{ background: {c.BG_MAIN}; border: none; }}"
            f"QScrollBar:vertical {{ background: {c.BG_DARK}; width: 6px; }}"
            f"QScrollBar::handle:vertical {{ background: {theme.DARK_ACCENT};"
            f" border-radius: 3px; min-height: 20px; }}"
        )

        content = QWidget()
        content.setStyleSheet(f"background: {c.BG_MAIN};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(4)

        layout.addWidget(_section_label("Provider"))
        layout.addWidget(self._build_provider_section())

        layout.addWidget(_separator())

        layout.addWidget(_section_label("Modell"))
        layout.addWidget(self._build_modell_section())

        layout.addWidget(_separator())

        layout.addWidget(_section_label("Erweitert"))
        layout.addWidget(self._build_advanced_section())

        layout.addSpacing(20)

        layout.addWidget(self._build_button_row())

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

    def _build_provider_section(self) -> QWidget:
        """Statischer Info-Block: Ollama lokal, Status-Indikator."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 4, 0, 8)
        layout.setSpacing(6)

        c = theme.get()
        row = QHBoxLayout()
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(8)

        provider_lbl = QLabel("Ollama (Lokal)")
        provider_lbl.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway';"
            f" font-size: 13px; font-weight: bold;"
        )
        row.addWidget(provider_lbl)

        self._status_label = QLabel("—")
        self._status_label.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        row.addWidget(self._status_label, stretch=1)

        wrapper = QWidget()
        wrapper.setLayout(row)
        layout.addWidget(wrapper)

        hinweis = QLabel(
            "NoRisk nutzt seit 28.05.2026 ausschliesslich lokale "
            "Ollama-Inferenz. Chat-Inhalte verlassen das Geraet nicht."
        )
        hinweis.setWordWrap(True)
        hinweis.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
        )
        layout.addWidget(hinweis)

        self._aktualisiere_provider_status()
        return w

    def _build_modell_section(self) -> QWidget:
        """Modell-Dropdown + Gemma-Empfehlung."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 4, 0, 8)
        layout.setSpacing(8)

        modell_row = QHBoxLayout()
        lbl = QLabel("Modell:")
        lbl.setFixedWidth(80)
        lbl.setStyleSheet(
            f"color: {theme.get().TEXT_MAIN}; font-family: 'Raleway'; font-size: 13px;"
        )
        modell_row.addWidget(lbl)

        self._combo_modell = QComboBox()
        self._combo_modell.setFixedHeight(32)
        self._combo_modell.setMinimumWidth(240)
        self._combo_modell.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self._combo_modell.setStyleSheet(_combo_style(theme.get()))
        modell_row.addWidget(self._combo_modell)

        btn_refresh = QPushButton()
        btn_refresh.setIcon(get_icon(Icons.REFRESH))
        btn_refresh.setFixedSize(32, 32)
        btn_refresh.setToolTip("Modell-Liste aktualisieren")
        btn_refresh.setStyleSheet(_btn_style(theme.get()))
        btn_refresh.clicked.connect(self._aktualisiere_modelle)
        modell_row.addWidget(btn_refresh)
        self._btn_modell_refresh = btn_refresh

        layout.addLayout(modell_row)

        self._gemma_hinweis = self._build_gemma_hinweis()
        self._gemma_hinweis.setVisible(False)
        layout.addWidget(self._gemma_hinweis)

        return w

    def _build_gemma_hinweis(self) -> QWidget:
        c = theme.get()
        box = QWidget()
        box.setStyleSheet(
            f"background: {c.BG_BUTTON}; border: 1px solid {c.ACCENT};"
            f" border-radius: 6px; padding: 8px;"
        )
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        row = QHBoxLayout()
        icon_lbl = QLabel("info")
        icon_lbl.setStyleSheet(
            "font-family: 'Material Symbols Outlined'; font-size: 18px;"
            f" color: {c.ACCENT}; background: transparent; border: none;"
        )
        row.addWidget(icon_lbl)

        title = QLabel("Empfehlung: Gemma 3 von Google")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            f" color: {c.ACCENT}; background: transparent; border: none;"
        )
        row.addWidget(title, stretch=1)
        layout.addLayout(row)

        desc = QLabel(
            "Gemma 3 ist Googles aktuelles leistungsfaehiges lokales Open-Source-"
            "Modell (Apache 2.0 Lizenz, keine Einschraenkungen).\n"
            "Installation: ollama pull gemma3"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 12px;"
            f" background: transparent; border: none;"
        )
        layout.addWidget(desc)

        btn_row = QHBoxLayout()
        btn_mehr = QPushButton("Mehr erfahren")
        btn_mehr.setIcon(get_icon(Icons.OPEN_IN_NEW))
        btn_mehr.setFixedHeight(28)
        btn_mehr.setStyleSheet(_btn_style(c))
        btn_mehr.clicked.connect(self._oeffne_gemma_link)
        btn_row.addWidget(btn_mehr)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return box

    def _build_advanced_section(self) -> QWidget:
        """Temperatur-Slider + Max-Tokens-Dropdown."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 4, 0, 8)
        layout.setSpacing(10)

        temp_row = QHBoxLayout()
        lbl_temp = QLabel("Temperatur:")
        lbl_temp.setFixedWidth(100)
        c = theme.get()
        lbl_temp.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 13px;"
        )
        temp_row.addWidget(lbl_temp)

        self._slider_temp = QSlider(Qt.Orientation.Horizontal)
        self._slider_temp.setRange(0, 200)  # 0.0–2.0 → ×100
        self._slider_temp.setSingleStep(5)
        self._slider_temp.setPageStep(10)
        self._slider_temp.setFixedHeight(20)
        self._slider_temp.setStyleSheet(
            f"QSlider::groove:horizontal {{ background: {c.BORDER}; height: 4px; border-radius: 2px; }}"
            f"QSlider::handle:horizontal {{ background: {c.ACCENT}; width: 14px; height: 14px;"
            f" margin: -5px 0; border-radius: 7px; }}"
            f"QSlider::sub-page:horizontal {{ background: {c.ACCENT}; height: 4px; border-radius: 2px; }}"
        )
        self._slider_temp.valueChanged.connect(self._on_temp_changed)
        temp_row.addWidget(self._slider_temp, stretch=1)

        self._lbl_temp_wert = QLabel("0.7")
        self._lbl_temp_wert.setFixedWidth(36)
        self._lbl_temp_wert.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._lbl_temp_wert.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'JetBrains Mono'; font-size: 13px; font-weight: bold;"
        )
        temp_row.addWidget(self._lbl_temp_wert)
        layout.addLayout(temp_row)

        tokens_row = QHBoxLayout()
        lbl_tok = QLabel("Max. Tokens:")
        lbl_tok.setFixedWidth(100)
        lbl_tok.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-family: 'Raleway'; font-size: 13px;"
        )
        tokens_row.addWidget(lbl_tok)

        self._combo_tokens = QComboBox()
        self._combo_tokens.setFixedHeight(32)
        self._combo_tokens.setFixedWidth(160)
        self._combo_tokens.setStyleSheet(_combo_style(c))
        for tok in _MAX_TOKENS_OPTIONEN:
            self._combo_tokens.addItem(str(tok), tok)
        tokens_row.addWidget(self._combo_tokens)
        tokens_row.addStretch()
        layout.addLayout(tokens_row)

        return w

    def _build_button_row(self) -> QWidget:
        """Speichern + Zurücksetzen-Buttons."""
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)

        c = theme.get()
        self._btn_speichern = QPushButton("Speichern")
        self._btn_speichern.setIcon(get_icon(Icons.SAVE))
        self._btn_speichern.setFixedHeight(36)
        self._btn_speichern.setStyleSheet(_btn_style(c, accent=True))
        self._btn_speichern.clicked.connect(self._speichern)
        layout.addWidget(self._btn_speichern)

        self._btn_reset = QPushButton("Zuruecksetzen")
        self._btn_reset.setIcon(get_icon(Icons.REFRESH))
        self._btn_reset.setFixedHeight(36)
        self._btn_reset.setStyleSheet(_btn_style(c))
        self._btn_reset.clicked.connect(self._zuruecksetzen)
        layout.addWidget(self._btn_reset)

        self._lbl_speichern_msg = QLabel("")
        self._lbl_speichern_msg.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.SUCCESS};"
        )
        layout.addWidget(self._lbl_speichern_msg)

        layout.addStretch()
        return row

    # ------------------------------------------------------------------
    # Werte laden / aktualisieren
    # ------------------------------------------------------------------

    def _lade_aktuelle_werte(self) -> None:
        """Fuellt alle Widgets mit den aktuell gespeicherten Werten."""
        if self._config is None:
            return

        self._aktualisiere_modelle()

        temp = self._config.temperatur()
        self._slider_temp.setValue(int(temp * 100))

        max_tok = self._config.max_tokens()
        for i, tok in enumerate(_MAX_TOKENS_OPTIONEN):
            if tok >= max_tok:
                self._combo_tokens.setCurrentIndex(i)
                break

    def _aktualisiere_provider_status(self) -> None:
        """Aktualisiert den Ollama-Status-Indikator."""
        c = theme.get()
        if self._provider is None:
            self._status_label.setText("Status unbekannt")
            self._status_label.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
            )
            return
        try:
            if self._provider.ist_verfuegbar():
                modelle = self._provider.verfuegbare_modelle()
                count = len(modelle)
                self._status_label.setText(
                    f"Verbunden — {count} Modell(e) installiert"
                )
                self._status_label.setStyleSheet(
                    f"color: {c.SUCCESS}; font-family: 'Raleway'; font-size: 12px;"
                )
            else:
                self._status_label.setText("Nicht erreichbar — ollama serve starten")
                self._status_label.setStyleSheet(
                    f"color: {c.ERROR}; font-family: 'Raleway'; font-size: 12px;"
                )
        except (RuntimeError, ConnectionError, OSError, AttributeError):
            self._status_label.setText("Status unbekannt")
            self._status_label.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-family: 'Raleway'; font-size: 12px;"
            )

    def _aktualisiere_modelle(self) -> None:
        """Befuellt den Modell-Dropdown."""
        if self._provider is None:
            return

        self._combo_modell.clear()
        try:
            modelle = self._provider.verfuegbare_modelle()
        except (RuntimeError, ConnectionError, OSError):
            modelle = []

        if modelle:
            for m in modelle:
                self._combo_modell.addItem(m)

            if self._config:
                gespeichertes = self._config.aktives_modell(_PROVIDER_ID)
                idx = self._combo_modell.findText(gespeichertes)
                if idx >= 0:
                    self._combo_modell.setCurrentIndex(idx)
        else:
            self._combo_modell.addItem("(Kein Modell — ollama pull gemma3)")

        self._aktualisiere_gemma_hinweis(modelle)

    def _aktualisiere_gemma_hinweis(self, modelle: list[str]) -> None:
        """Zeigt/versteckt den Gemma-3-Empfehlungsblock."""
        from core.ollama_utils import DEFAULT_OLLAMA_MODEL  # noqa: PLC0415

        zeigen = not any(
            m.lower().startswith(DEFAULT_OLLAMA_MODEL) for m in modelle
        )
        self._gemma_hinweis.setVisible(zeigen)

    # ------------------------------------------------------------------
    # Event-Handler
    # ------------------------------------------------------------------

    def _on_temp_changed(self, wert: int) -> None:
        self._lbl_temp_wert.setText(f"{wert / 100:.2f}")

    def _oeffne_gemma_link(self) -> None:
        """Oeffnet die Gemma-4 Infoseite im Browser."""
        import webbrowser  # noqa: PLC0415

        webbrowser.open(_GEMMA_EMPFEHLUNG_URL)

    # ------------------------------------------------------------------
    # Speichern / Zuruecksetzen
    # ------------------------------------------------------------------

    def _speichern(self) -> None:
        """Speichert alle Ollama-Einstellungen."""
        c = theme.get()
        if self._config is None:
            return

        try:
            self._config.setze_provider(_PROVIDER_ID)

            modell = self._combo_modell.currentText()
            if modell and not modell.startswith("("):
                self._config.setze_modell(_PROVIDER_ID, modell)

            temp = self._slider_temp.value() / 100.0
            self._config.setze_temperatur(temp)

            max_tok_data = self._combo_tokens.currentData()
            if max_tok_data is not None:
                self._config.setze_max_tokens(int(max_tok_data))

            self._lbl_speichern_msg.setText("Einstellungen gespeichert.")
            self._lbl_speichern_msg.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 13px; color: {c.SUCCESS};"
            )
            _log.info("LLM-Einstellungen gespeichert (Provider: %s)", _PROVIDER_ID)

            try:
                from core.llm import invalidate_llm_cache  # noqa: PLC0415

                invalidate_llm_cache()
            except (ImportError, RuntimeError):
                _log.debug("LLM-Cache-Invalidierung fehlgeschlagen (nicht kritisch)")

            self._provider = self._lade_provider()
            self._aktualisiere_provider_status()

        except (OSError, RuntimeError, ValueError) as exc:
            _log.exception("Fehler beim Speichern der LLM-Einstellungen: %s", exc)
            self._lbl_speichern_msg.setText(f"Fehler: {exc}")
            self._lbl_speichern_msg.setStyleSheet(
                f"font-family: 'Raleway'; font-size: 13px; color: {c.ERROR};"
            )

    def _zuruecksetzen(self) -> None:
        """Stellt Default-Werte wieder her."""
        if self._config is None:
            return

        from core.llm.llm_config import LLMProviderConfig  # noqa: PLC0415

        c = theme.get()

        self._slider_temp.setValue(int(LLMProviderConfig.DEFAULT_TEMPERATURE * 100))

        default_tok = LLMProviderConfig.DEFAULT_MAX_TOKENS
        for i, tok in enumerate(_MAX_TOKENS_OPTIONEN):
            if tok >= default_tok:
                self._combo_tokens.setCurrentIndex(i)
                break

        self._aktualisiere_modelle()

        self._lbl_speichern_msg.setText(
            "Defaults wiederhergestellt — bitte Speichern klicken."
        )
        self._lbl_speichern_msg.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px; color: {c.WARNING};"
        )

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben fuer das aktive Theme."""
        c = theme.get()

        self._combo_modell.setStyleSheet(_combo_style(c))
        self._combo_tokens.setStyleSheet(_combo_style(c))
        self._btn_modell_refresh.setStyleSheet(_btn_style(c))

        self._slider_temp.setStyleSheet(
            f"QSlider::groove:horizontal {{ background: {c.BORDER}; height: 4px; border-radius: 2px; }}"
            f"QSlider::handle:horizontal {{ background: {c.ACCENT}; width: 14px; height: 14px;"
            f" margin: -5px 0; border-radius: 7px; }}"
            f"QSlider::sub-page:horizontal {{ background: {c.ACCENT}; height: 4px; border-radius: 2px; }}"
        )
        self._lbl_temp_wert.setStyleSheet(
            f"color: {c.ACCENT}; font-family: 'JetBrains Mono'; font-size: 13px; font-weight: bold;"
        )

        self._btn_speichern.setStyleSheet(_btn_style(c, accent=True))
        self._btn_reset.setStyleSheet(_btn_style(c))

        self._aktualisiere_provider_status()
