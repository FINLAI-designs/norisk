"""
assessment_wizard — Geführter 5-Schritte Security Assessment Wizard.

Führt den User durch:
  ① Klient — bestehenden wählen oder neuen eingeben
  ② Bereiche — Testbereiche aktivieren/deaktivieren
  ③ Test — Tests laufen sequenziell im Hintergrund
  ④ Ergebnis — Gesamt-Score + Aufschlüsselung je Bereich
  ⑤ Report — PDF-Export + Clipboard-Kopie + Schließen

Schichtzugehörigkeit: gui/ — kein Business-Logik, nur UI und QThread-Steuerung.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import copy
from datetime import date
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.dialogs import (
    FinlaiConfirmDialog,
    FinlaiInfoDialog,
    FinlaiSuccessDialog,
)
from core.icons import Icons, get_icon
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.security_scoring.domain.models import SecurityScore
from tools.security_scoring.domain.scoring_engine import score_to_grade
from tools.security_scoring.gui.dialogs.assessment_runner import (
    TESTBEREICHE,
    AssessmentRunner,
)

if TYPE_CHECKING:
    from PySide6.QtWidgets import QComboBox

    from tools.security_scoring.domain.interfaces import IScoreRepository

# ---------------------------------------------------------------------------
# Noten-Farben
# ---------------------------------------------------------------------------

_GRADE_COLORS: dict[str, str] = {
    "A": theme.GRADE_A,
    "B": theme.GRADE_B,
    "C": theme.GRADE_C,
    "D": theme.GRADE_D,
    "F": theme.GRADE_F,
}

_GRADE_TEXT: dict[str, str] = {
    "A": "Sehr gutes Sicherheitsniveau",
    "B": "Gutes Sicherheitsniveau",
    "C": "Ausreichendes Sicherheitsniveau",
    "D": "Verbesserungsbedürftiges Sicherheitsniveau",
    "F": "Kritisches Sicherheitsniveau — sofortige Maßnahmen erforderlich",
}


# ---------------------------------------------------------------------------
# Stepper-Widget (①②③④⑤ Navigation)
# ---------------------------------------------------------------------------


class _StepperWidget(QWidget):
    """Zeigt die 5 Wizard-Schritte als horizontale Schritt-Leiste.

    Attributes:
        _labels: Schrittbezeichnungen.
        _schritt: Aktuell aktiver Schritt (0-based).
        _erledigt: Set erledigter Schrittindizes.
    """

    _ZIFFERN = ["①", "②", "③", "④", "⑤"]

    def __init__(self, labels: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._labels = labels
        self._schritt = 0
        self._erledigt: set[int] = set()
        self._label_widgets: list[QLabel] = []
        self._build_ui()

    def _build_ui(self) -> None:
        c = theme.get()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(0)

        for i, lbl in enumerate(self._labels):
            # Schritt-Label
            step_lbl = QLabel(f"{self._ZIFFERN[i]}  {lbl}")
            step_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            step_lbl.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 11px; padding: 2px 4px;"
            )
            self._label_widgets.append(step_lbl)
            layout.addWidget(step_lbl, stretch=1)

            # Trennstrich (nicht nach letztem)
            if i < len(self._labels) - 1:
                sep = QLabel("─")
                sep.setAlignment(Qt.AlignmentFlag.AlignCenter)
                sep.setStyleSheet(f"color: {c.BORDER}; font-size: 14px;")
                layout.addWidget(sep)

        self._aktualisiere()

    def setze_schritt(self, schritt: int) -> None:
        """Aktualisiert den aktiven Schritt.

        Args:
            schritt: Neuer aktiver Schritt (0-based).
        """
        if schritt > self._schritt:
            self._erledigt.add(self._schritt)
        self._schritt = schritt
        self._aktualisiere()

    def _aktualisiere(self) -> None:
        c = theme.get()
        for i, lbl in enumerate(self._label_widgets):
            if i in self._erledigt:
                lbl.setStyleSheet(
                    f"color: {theme.SEVERITY_SIGNAL_OK}; font-size: 11px;"
                    " padding: 2px 4px; font-weight: 600;"
                )
                lbl.setText(f"OK  {self._labels[i]}")
            elif i == self._schritt:
                lbl.setStyleSheet(
                    f"color: {c.ACCENT}; font-size: 11px; padding: 2px 4px;"
                    f" font-weight: 700; border-bottom: 2px solid {c.ACCENT};"
                )
                lbl.setText(f"{self._ZIFFERN[i]}  {self._labels[i]}")
            else:
                lbl.setStyleSheet(
                    f"color: {c.TEXT_DIM}; font-size: 11px; padding: 2px 4px;"
                )
                lbl.setText(f"{self._ZIFFERN[i]}  {self._labels[i]}")


# ---------------------------------------------------------------------------
# Schritt 3: Einzel-Test-Zeile
# ---------------------------------------------------------------------------


class _TestZeile(QWidget):
    """Zeigt Status und Fortschritt eines einzelnen Testbereichs.

    Attributes:
        _name: Anzeigename des Bereichs.
    """

    def __init__(self, icon: str, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._name = name
        c = theme.get()

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        # Icon + Name
        self._lbl_icon = QLabel(icon)
        self._lbl_icon.setFixedWidth(20)
        layout.addWidget(self._lbl_icon)

        name_lbl = QLabel(name)
        name_lbl.setFixedWidth(160)
        name_lbl.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 12px;")
        layout.addWidget(name_lbl)

        # Fortschrittsbalken: kanonischer FinlaiProgressBar)
        self._progress = FinlaiProgressBar(total=100)
        self._progress.setFixedWidth(140)
        layout.addWidget(self._progress)

        # Score + Status
        self._lbl_score = QLabel("—")
        self._lbl_score.setFixedWidth(55)
        self._lbl_score.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._lbl_score.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-family: monospace;"
        )
        layout.addWidget(self._lbl_score)

        self._lbl_status = QLabel("wartend")
        self._lbl_status.setFixedWidth(80)
        self._lbl_status.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        layout.addWidget(self._lbl_status)

        layout.addStretch()

    def setze_laufend(self) -> None:
        """Markiert den Test als laufend."""
        c = theme.get()
        self._lbl_status.setStyleSheet(f"color: {c.ACCENT}; font-size: 11px;")
        self._lbl_status.setText("läuft …")
        self._progress.setRange(0, 0)  # Indeterminate

    def setze_fortschritt(self, prozent: int) -> None:
        """Aktualisiert den Fortschrittsbalken.

        Args:
            prozent: 0–100.
        """
        self._progress.setRange(0, 100)
        self._progress.setValue(prozent)

    def setze_fertig(self, score: float) -> None:
        """Markiert den Test als abgeschlossen.

        Args:
            score: Erreicher Score 0–100.
        """
        self._progress.setRange(0, 100)
        self._progress.setValue(100)
        self._lbl_score.setText(f"{score:.0f}/100")
        grade = score_to_grade(score)
        farbe = _GRADE_COLORS.get(grade, theme.SEVERITY_SIGNAL_INFO)
        self._lbl_score.setStyleSheet(
            f"color: {farbe}; font-size: 11px; font-weight: bold; font-family: monospace;"
        )
        self._lbl_status.setText("Fertig")
        self._lbl_status.setStyleSheet(
            f"color: {theme.get().SUCCESS}; font-size: 11px;"
        )

    def setze_fehler(self) -> None:
        """Markiert den Test als fehlgeschlagen."""
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._lbl_score.setText("—")
        self._lbl_status.setText("[WARN] Fehler")
        self._lbl_status.setStyleSheet(
            f"color: {theme.get().WARNING}; font-size: 11px;"
        )


# ---------------------------------------------------------------------------
# AssessmentWizard
# ---------------------------------------------------------------------------


class AssessmentWizard(QDialog):
    """Geführter 5-Schritte Security Assessment Wizard.

    Attributes:
        _services: Dict mit Service-Instanzen je Tool-Schlüssel.
        _score_repo: Optionales Repository für Score-Persistenz.
        _klient: Ausgewählter/eingegebener Klientenname.
        _bereiche: Aktive Bereich-Dicts (Kopien aus TESTBEREICHE).
        _ergebnis: Berechneter SecurityScore nach Abschluss.
        _runner: Aktiver AssessmentRunner-Thread oder None.
    """

    def __init__(
        self,
        services: dict,
        bekannte_targets: list[str] | None = None,
        score_repo: IScoreRepository | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Wizard.

        Args:
            services: Dict mit Service-Instanzen (keys: api_security,
                              network_scanner, cert_monitor, dependency_auditor,
                              system_scanner).
            bekannte_targets: Vorhandene Klientennamen für das Dropdown.
            score_repo: Repository zum Speichern des Ergebnisses.
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._services = services
        self._bekannte_targets = bekannte_targets or []
        self._score_repo = score_repo
        self._klient: str = ""
        self._bereiche: list[dict] = [copy.copy(b) for b in TESTBEREICHE]
        self._ergebnis: SecurityScore | None = None
        self._runner: AssessmentRunner | None = None
        self._test_zeilen: dict[str, _TestZeile] = {}

        self.setWindowTitle("Security Assessment")
        self.setMinimumSize(600, 460)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )
        self._build_ui()
        self._apply_theme()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt das gesamte Wizard-Layout."""
        c = theme.get()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QWidget()
        header.setStyleSheet(f"background-color: {c.BG_DARK};")
        header_lyt = QVBoxLayout(header)
        header_lyt.setContentsMargins(20, 12, 20, 8)

        self._lbl_titel = QLabel("Security Assessment")
        self._lbl_titel.setStyleSheet(
            f"color: {c.ACCENT}; font-size: 16px; font-weight: bold;"
        )
        header_lyt.addWidget(self._lbl_titel)

        self._stepper = _StepperWidget(
            ["System", "Bereiche", "Test", "Ergebnis", "Report"]
        )
        header_lyt.addWidget(self._stepper)
        root.addWidget(header)

        # Trennlinie
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {c.ACCENT}; min-height: 1px;")
        root.addWidget(sep)

        # Content-Stack
        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_schritt_klient())
        self._stack.addWidget(self._build_schritt_bereiche())
        self._stack.addWidget(self._build_schritt_test())
        self._stack.addWidget(self._build_schritt_ergebnis())
        self._stack.addWidget(self._build_schritt_report())
        root.addWidget(self._stack, stretch=1)

        # Fußzeile: Navigations-Buttons
        footer = QWidget()
        footer.setStyleSheet(f"background-color: {c.BG_DARK};")
        footer_lyt = QHBoxLayout(footer)
        footer_lyt.setContentsMargins(20, 10, 20, 10)

        self._btn_zurueck = QPushButton("Zurück")
        self._btn_zurueck.setEnabled(False)
        self._btn_zurueck.clicked.connect(self._on_zurueck)
        footer_lyt.addWidget(self._btn_zurueck)

        footer_lyt.addStretch()

        self._btn_abbrechen = QPushButton("Abbrechen")
        self._btn_abbrechen.clicked.connect(self._on_abbrechen)
        footer_lyt.addWidget(self._btn_abbrechen)

        self._btn_weiter = QPushButton("Weiter")
        self._btn_weiter.setEnabled(False)
        self._btn_weiter.clicked.connect(self._on_weiter)
        footer_lyt.addWidget(self._btn_weiter)

        root.addWidget(footer)
        self._apply_button_styles()

        # Initialen Weiter-Zustand setzen (Schritt 1: Klient)
        if self._bekannte_targets:
            self._btn_weiter.setEnabled(True)

    def _apply_button_styles(self) -> None:
        c = theme.get()
        _std = (
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 6px 16px; min-width: 80px; }}"
            f"QPushButton:hover {{ background-color: {c.BG_INPUT};"
            f" border-color: {c.ACCENT}; color: {theme.DARK_TEXT_ON_ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT};"
            f" color: {c.BG_DARK}; padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; border-color: {c.BORDER}; }}"
        )
        _primary = (
            f"QPushButton {{ background-color: {c.ACCENT}; color: {c.BG_DARK};"
            f" border: none; border-radius: 4px; padding: 6px 16px;"
            f" min-width: 100px; font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {c.ACCENT_DIM}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT_DARK};"
            f" padding-top: 7px; padding-bottom: 5px; }}"
            f"QPushButton:disabled {{ background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_BUTTON_DISABLED}; }}"
        )
        self._btn_zurueck.setStyleSheet(_std)
        self._btn_abbrechen.setStyleSheet(_std)
        self._btn_weiter.setStyleSheet(_primary)

    def _apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QDialog {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QLabel {{ color: {c.TEXT_MAIN}; }}"
            f"QScrollArea {{ border: none; background: transparent; }}"
        )
        self._apply_button_styles()

    # ------------------------------------------------------------------
    # Schritt 1: Klient
    # ------------------------------------------------------------------

    def _build_schritt_klient(self) -> QWidget:
        """Erstellt den Klient-Auswahl-Schritt."""
        c = theme.get()
        widget = QWidget()
        lyt = QVBoxLayout(widget)
        lyt.setContentsMargins(24, 20, 24, 20)
        lyt.setSpacing(12)

        hdr = QLabel("System für dieses Assessment:")
        hdr.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 13px; font-weight: 600;")
        lyt.addWidget(hdr)

        # Radio: bestehender Klient
        self._radio_bestehend = QRadioButton("Bestehendes System")
        self._radio_bestehend.setStyleSheet(f"color: {c.TEXT_MAIN};")
        self._radio_bestehend.setChecked(True)
        self._radio_bestehend.toggled.connect(self._on_klient_modus_changed)
        lyt.addWidget(self._radio_bestehend)

        # Dropdown für bestehende Klienten (importiert lazy)
        from PySide6.QtWidgets import QComboBox  # noqa: PLC0415

        self._combo_klient: QComboBox = QComboBox()
        self._combo_klient.setEditable(False)
        self._combo_klient.setMinimumWidth(280)
        self._combo_klient.addItems(self._bekannte_targets)
        if not self._bekannte_targets:
            self._combo_klient.addItem("(keine Systeme vorhanden)")
            self._combo_klient.setEnabled(False)
        self._combo_klient.setStyleSheet(
            f"QComboBox {{ background-color: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 8px; }}"
            f"QComboBox::drop-down {{ border: none; }}"
            f"QComboBox QAbstractItemView {{ background-color: {c.BG_INPUT};"
            f" color: {c.TEXT_MAIN}; selection-background-color: {c.ACCENT};"
            f" selection-color: {c.BG_DARK}; }}"
        )
        self._combo_klient.currentTextChanged.connect(self._on_klient_text_changed)
        lyt.addWidget(self._combo_klient)

        # Radio: neuer Klient
        self._radio_neu = QRadioButton("Neues System")
        self._radio_neu.setStyleSheet(f"color: {c.TEXT_MAIN};")
        lyt.addWidget(self._radio_neu)

        from PySide6.QtWidgets import QLineEdit  # noqa: PLC0415

        self._input_klient_name = QLineEdit()
        self._input_klient_name.setPlaceholderText("Name des Systems eingeben …")
        self._input_klient_name.setEnabled(False)
        self._input_klient_name.setMinimumWidth(280)
        self._input_klient_name.setStyleSheet(
            f"QLineEdit {{ background-color: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 5px 8px; }}"
            f"QLineEdit:focus {{ border-color: {c.ACCENT}; }}"
            f"QLineEdit:disabled {{ background-color: {c.BG_BUTTON_DISABLED};"
            f" color: {c.TEXT_DIM}; }}"
        )
        self._input_klient_name.textChanged.connect(self._on_klient_text_changed)
        lyt.addWidget(self._input_klient_name)

        lyt.addStretch()

        return widget

    # ------------------------------------------------------------------
    # Schritt 2: Bereiche
    # ------------------------------------------------------------------

    def _build_schritt_bereiche(self) -> QWidget:
        """Erstellt den Testbereiche-Auswahl-Schritt."""
        c = theme.get()
        widget = QWidget()
        lyt = QVBoxLayout(widget)
        lyt.setContentsMargins(24, 20, 24, 20)
        lyt.setSpacing(8)

        hdr = QLabel("Welche Bereiche sollen geprüft werden?")
        hdr.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 13px; font-weight: 600;")
        lyt.addWidget(hdr)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        inner_lyt = QVBoxLayout(inner)
        inner_lyt.setSpacing(6)
        inner_lyt.setContentsMargins(0, 4, 0, 4)

        self._bereich_checkboxen: dict[str, QCheckBox] = {}

        for bereich in self._bereiche:
            key = bereich["key"]
            cb_row = QWidget()
            cb_lyt = QHBoxLayout(cb_row)
            cb_lyt.setContentsMargins(0, 0, 0, 0)
            cb_lyt.setSpacing(10)

            cb = QCheckBox(
                f"{bereich['icon']}  {bereich['name']}"
                f"   ({bereich['gewichtung'] * 100:.0f}%)"
            )
            cb.setChecked(bereich["standard_aktiv"])
            cb.setStyleSheet(
                f"QCheckBox {{ color: {c.TEXT_MAIN}; font-size: 12px;"
                f" font-weight: 600; spacing: 8px; }}"
                f"QCheckBox::indicator {{ width: 16px; height: 16px;"
                f" border: 2px solid {c.BORDER}; border-radius: 3px;"
                f" background-color: {c.BG_INPUT}; }}"
                f"QCheckBox::indicator:hover {{ border-color: {c.ACCENT}; }}"
                f"QCheckBox::indicator:checked {{ background-color: {c.ACCENT};"
                f" border-color: {c.ACCENT}; }}"
            )
            cb.stateChanged.connect(self._on_bereiche_changed)
            self._bereich_checkboxen[key] = cb
            cb_lyt.addWidget(cb, stretch=1)

            inner_lyt.addWidget(cb_row)

            desc_lbl = QLabel(f"     {bereich['beschreibung']}")
            desc_lbl.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 11px; padding-left: 28px;"
            )
            inner_lyt.addWidget(desc_lbl)

        inner_lyt.addStretch()
        scroll.setWidget(inner)
        lyt.addWidget(scroll, stretch=1)

        # Scanner-Status-Info (für Systemsicherheit-Bereich)
        self._lbl_scanner_status = QLabel("")
        self._lbl_scanner_status.setWordWrap(True)
        self._lbl_scanner_status.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 6px 10px; background: {c.BG_INPUT};"
        )
        self._lbl_scanner_status.setVisible(False)
        lyt.addWidget(self._lbl_scanner_status)

        self._lbl_bereiche_hinweis = QLabel(
            "Mindestens 1 Bereich muss ausgewählt sein."
        )
        self._lbl_bereiche_hinweis.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        lyt.addWidget(self._lbl_bereiche_hinweis)

        # Scanner-Status initial laden
        self._aktualisiere_scanner_status()

        return widget

    def _aktualisiere_scanner_status(self) -> None:
        """Prüft und zeigt den Systemscanner-Status im Bereiche-Schritt."""
        from datetime import UTC, datetime  # noqa: PLC0415

        from core import theme as _theme  # noqa: PLC0415

        c = _theme.get()
        _MAX_ALTER_TAGE = 30

        try:
            from tools.system_scanner.application.scan_history_use_case import (  # noqa: PLC0415
                create_default_scan_history_use_case,
            )

            result = create_default_scan_history_use_case().get_latest()
        except (ImportError, OSError, RuntimeError):
            self._lbl_scanner_status.setVisible(False)
            return

        if result is None:
            self._lbl_scanner_status.setText(
                "Hinweis: Systemsicherheit — Kein Scan vorhanden."
                " Bitte zuerst 'Scan starten' ausführen."
                " Score wird mit 50/100 angenommen."
            )
            self._lbl_scanner_status.setStyleSheet(
                f"color: {c.WARNING}; font-size: 11px;"
                f" border: 1px solid {c.WARNING}; border-radius: 4px;"
                f" padding: 6px 10px; background: {c.BG_INPUT};"
            )
            self._lbl_scanner_status.setVisible(True)
            return

        alter_tage = (datetime.now(tz=UTC) - result.timestamp).days
        if alter_tage > _MAX_ALTER_TAGE:
            self._lbl_scanner_status.setText(
                f"Hinweis: Systemsicherheit — Letzter Scan ist {alter_tage} Tage alt"
                f" (Limit: {_MAX_ALTER_TAGE} Tage)."
                " Bitte neuen Scan durchführen. Score wird mit 50/100 angenommen."
            )
            self._lbl_scanner_status.setStyleSheet(
                f"color: {c.WARNING}; font-size: 11px;"
                f" border: 1px solid {c.WARNING}; border-radius: 4px;"
                f" padding: 6px 10px; background: {c.BG_INPUT};"
            )
            self._lbl_scanner_status.setVisible(True)
        else:
            self._lbl_scanner_status.setText(
                f"OK: Systemsicherheit — Letzter Scan vom"
                f" {result.timestamp.strftime('%d.%m.%Y %H:%M')}"
                f" ({alter_tage} Tage alt,"
                f" {len(result.security_components)} Komponenten erkannt)"
            )
            self._lbl_scanner_status.setStyleSheet(
                f"color: {c.SUCCESS}; font-size: 11px;"
                f" border: 1px solid {c.SUCCESS}; border-radius: 4px;"
                f" padding: 6px 10px; background: {c.BG_INPUT};"
            )
            self._lbl_scanner_status.setVisible(True)

    # ------------------------------------------------------------------
    # Schritt 3: Test
    # ------------------------------------------------------------------

    def _build_schritt_test(self) -> QWidget:
        """Erstellt den Test-Fortschritts-Schritt."""
        c = theme.get()
        widget = QWidget()
        lyt = QVBoxLayout(widget)
        lyt.setContentsMargins(24, 20, 24, 20)
        lyt.setSpacing(10)

        self._lbl_test_header = QLabel("Tests laufen …")
        self._lbl_test_header.setStyleSheet(
            f"color: {c.TEXT_MAIN}; font-size: 13px; font-weight: 600;"
        )
        lyt.addWidget(self._lbl_test_header)

        # Test-Zeilen (werden beim Starten befüllt)
        self._test_zeilen_container = QWidget()
        self._test_zeilen_lyt = QVBoxLayout(self._test_zeilen_container)
        self._test_zeilen_lyt.setSpacing(6)
        self._test_zeilen_lyt.setContentsMargins(0, 0, 0, 0)
        lyt.addWidget(self._test_zeilen_container)

        lyt.addStretch()

        # Gesamt-Fortschritt
        gesamt_lbl = QLabel("Gesamtfortschritt:")
        gesamt_lbl.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
        lyt.addWidget(gesamt_lbl)

        # kanonischer FinlaiProgressBar — Wizard-Sonderfall mit
        # 16 px + Text-Anzeige (Prozent), damit die Restzeit-Box visuell
        # zur Bar passt.
        self._progress_gesamt = FinlaiProgressBar(total=100)
        self._progress_gesamt.setFixedHeight(16)
        self._progress_gesamt.setTextVisible(True)
        lyt.addWidget(self._progress_gesamt)

        self._lbl_restzeit = QLabel("")
        self._lbl_restzeit.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; qproperty-alignment: AlignRight;"
        )
        lyt.addWidget(self._lbl_restzeit)

        return widget

    # ------------------------------------------------------------------
    # Schritt 4: Ergebnis
    # ------------------------------------------------------------------

    def _build_schritt_ergebnis(self) -> QWidget:
        """Erstellt den Ergebnis-Übersicht-Schritt."""
        c = theme.get()
        widget = QWidget()
        lyt = QVBoxLayout(widget)
        lyt.setContentsMargins(24, 16, 24, 16)
        lyt.setSpacing(10)

        # Score-Anzeige oben
        score_row = QHBoxLayout()
        score_row.setSpacing(20)

        self._score_box = QWidget()
        self._score_box.setFixedSize(110, 90)
        self._score_box.setStyleSheet(
            f"background-color: {c.BG_INPUT}; border: 2px solid {c.BORDER};"
            f" border-radius: 8px;"
        )
        score_box_lyt = QVBoxLayout(self._score_box)
        score_box_lyt.setContentsMargins(4, 4, 4, 4)

        self._lbl_score_zahl = QLabel("—")
        self._lbl_score_zahl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_score_zahl.setStyleSheet(
            f"font-size: 28px; font-weight: bold;"
            f" color: {theme.SEVERITY_SIGNAL_INFO}; border: none;"
        )
        score_box_lyt.addWidget(self._lbl_score_zahl)

        self._lbl_score_sub = QLabel("/100")
        self._lbl_score_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_score_sub.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; border: none;"
        )
        score_box_lyt.addWidget(self._lbl_score_sub)

        score_row.addWidget(self._score_box)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)

        self._lbl_note = QLabel("Note: —")
        self._lbl_note.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {theme.SEVERITY_SIGNAL_INFO};"
        )
        info_col.addWidget(self._lbl_note)

        self._lbl_note_text = QLabel("")
        self._lbl_note_text.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 12px;")
        self._lbl_note_text.setWordWrap(True)
        info_col.addWidget(self._lbl_note_text)

        info_col.addStretch()
        score_row.addLayout(info_col, stretch=1)
        lyt.addLayout(score_row)

        # Trennlinie
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {c.BORDER}; min-height: 1px;")
        lyt.addWidget(sep)

        # Komponenten-Aufschlüsselung (scrollbar)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._ergebnis_inner = QWidget()
        self._ergebnis_lyt = QVBoxLayout(self._ergebnis_inner)
        self._ergebnis_lyt.setSpacing(4)
        self._ergebnis_lyt.setContentsMargins(0, 0, 0, 0)
        scroll.setWidget(self._ergebnis_inner)
        lyt.addWidget(scroll, stretch=1)

        # Zusammenfassung
        self._lbl_zusammenfassung = QLabel("")
        self._lbl_zusammenfassung.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px;"
        )
        lyt.addWidget(self._lbl_zusammenfassung)

        return widget

    # ------------------------------------------------------------------
    # Schritt 5: Report
    # ------------------------------------------------------------------

    def _build_schritt_report(self) -> QWidget:
        """Erstellt den Abschluss-Report-Schritt."""
        c = theme.get()
        widget = QWidget()
        lyt = QVBoxLayout(widget)
        lyt.setContentsMargins(24, 20, 24, 20)
        lyt.setSpacing(12)

        self._lbl_abschluss = QLabel("Assessment abgeschlossen!")
        self._lbl_abschluss.setStyleSheet(
            f"color: {theme.SEVERITY_SIGNAL_OK}; font-size: 14px; font-weight: bold;"
        )
        lyt.addWidget(self._lbl_abschluss)

        self._lbl_report_info = QLabel("")
        self._lbl_report_info.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 12px;")
        self._lbl_report_info.setWordWrap(True)
        lyt.addWidget(self._lbl_report_info)

        self._lbl_gespeichert = QLabel("Score wurde gespeichert.")
        self._lbl_gespeichert.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: 11px; font-style: italic;"
        )
        lyt.addWidget(self._lbl_gespeichert)

        lyt.addSpacing(8)

        btn_pdf = QPushButton("PDF-Report erstellen")
        btn_pdf.setIcon(get_icon(Icons.PDF))
        btn_pdf.setMinimumHeight(38)
        btn_pdf.setStyleSheet(
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 6px 16px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: {c.BG_INPUT};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT};"
            f" color: {c.BG_DARK}; }}"
        )
        btn_pdf.clicked.connect(self._on_pdf_export)
        lyt.addWidget(btn_pdf)

        btn_clipboard = QPushButton("Ergebnisse in Zwischenablage kopieren")
        btn_clipboard.setIcon(get_icon(Icons.COPY))
        btn_clipboard.setMinimumHeight(38)
        btn_clipboard.setStyleSheet(
            f"QPushButton {{ background-color: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 6px 16px; font-size: 12px; }}"
            f"QPushButton:hover {{ background-color: {c.BG_INPUT};"
            f" border-color: {c.ACCENT}; }}"
            f"QPushButton:pressed {{ background-color: {c.ACCENT};"
            f" color: {c.BG_DARK}; }}"
        )
        btn_clipboard.clicked.connect(self._on_clipboard_kopieren)
        lyt.addWidget(btn_clipboard)

        lyt.addStretch()
        return widget

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _zeige_schritt(self, schritt: int) -> None:
        """Wechselt zum angegebenen Schritt.

        Args:
            schritt: Ziel-Schritt 0-based (0–4).
        """
        self._stack.setCurrentIndex(schritt)
        self._stepper.setze_schritt(schritt)
        self._lbl_titel.setText(
            "Security Assessment"
            + (f" — {self._klient}" if self._klient and schritt > 0 else "")
        )

        is_last = schritt == 4
        self._btn_zurueck.setVisible(schritt in (1, 3))
        self._btn_weiter.setVisible(not is_last and schritt != 2)
        self._btn_abbrechen.setVisible(schritt != 4)

        if is_last:
            # Schließen-Button
            self._btn_weiter.setVisible(True)
            self._btn_weiter.setText("Schließen")
            self._btn_weiter.setEnabled(True)
            self._btn_weiter.clicked.disconnect()
            self._btn_weiter.clicked.connect(self.accept)

        # Schritt-spezifische Updates
        if schritt == 1:
            self._btn_weiter.setText("Weiter")
            self._on_bereiche_changed()
        elif schritt == 2:
            self._starte_tests()
        elif schritt == 3 and self._ergebnis:
            self._zeige_ergebnis(self._ergebnis)
            self._btn_weiter.setText("Report")
            self._btn_weiter.setEnabled(True)
        elif schritt == 4 and self._ergebnis:
            self._zeige_report_info(self._ergebnis)

    @Slot()
    def _on_weiter(self) -> None:
        """Behandelt Klick auf 'Weiter'."""
        aktuell = self._stack.currentIndex()
        if aktuell == 0:
            # Klientennamen festlegen
            if self._radio_neu.isChecked():
                self._klient = self._input_klient_name.text().strip()
            else:
                self._klient = self._combo_klient.currentText()
            if not self._klient or self._klient == "(keine Systeme vorhanden)":
                return
            self._zeige_schritt(1)
        elif aktuell == 1:
            aktiv = [
                b
                for b in self._bereiche
                if self._bereich_checkboxen[b["key"]].isChecked()
            ]
            if not aktiv:
                return
            self._bereiche_aktiv = aktiv
            self._zeige_schritt(2)
        elif aktuell == 3:
            self._zeige_schritt(4)

    @Slot()
    def _on_zurueck(self) -> None:
        """Behandelt Klick auf 'Zurück'."""
        aktuell = self._stack.currentIndex()
        if aktuell == 1:
            self._zeige_schritt(0)
        elif aktuell == 3:
            self._zeige_schritt(1)

    @Slot()
    def _on_abbrechen(self) -> None:
        """Bricht den Wizard ab (mit Bestätigung während laufender Tests)."""
        if self._runner and self._runner.isRunning():
            dlg = FinlaiConfirmDialog(
                title="Assessment abbrechen?",
                message=(
                    "Die Tests laufen noch. Wirklich abbrechen?\n"
                    "Der aktuelle Test wird noch abgeschlossen."
                ),
                confirm_text="Assessment abbrechen",
                cancel_text="Weiter testen",
                parent=self,
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            self._runner.abbrechen()
        self.reject()

    # ------------------------------------------------------------------
    # Schritt 1: Klient-Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_klient_modus_changed(self) -> None:
        """Schaltet zwischen bestehendem und neuem Klient um."""
        neu = self._radio_neu.isChecked()
        self._combo_klient.setEnabled(not neu and bool(self._bekannte_targets))
        self._input_klient_name.setEnabled(neu)
        self._on_klient_text_changed()

    @Slot()
    def _on_klient_text_changed(self) -> None:
        """Aktiviert Weiter-Button wenn Klientenname vorhanden."""
        if self._radio_neu.isChecked():
            ok = bool(self._input_klient_name.text().strip())
        else:
            text = self._combo_klient.currentText()
            ok = bool(text) and text != "(keine Systeme vorhanden)"
        self._btn_weiter.setEnabled(ok)

    # ------------------------------------------------------------------
    # Schritt 2: Bereiche-Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_bereiche_changed(self) -> None:
        """Aktiviert Weiter-Button wenn mindestens 1 Bereich gewählt."""
        aktiv = sum(1 for cb in self._bereich_checkboxen.values() if cb.isChecked())
        self._btn_weiter.setEnabled(aktiv > 0)
        if aktiv == 0:
            self._lbl_bereiche_hinweis.setStyleSheet(
                f"color: {theme.get().ERROR}; font-size: 11px;"
            )
        else:
            c = theme.get()
            self._lbl_bereiche_hinweis.setStyleSheet(
                f"color: {c.TEXT_DIM}; font-size: 11px;"
            )

    # ------------------------------------------------------------------
    # Schritt 3: Tests
    # ------------------------------------------------------------------

    def _starte_tests(self) -> None:
        """Baut Test-Zeilen auf und startet den AssessmentRunner-Thread."""
        # Zeilen aufräumen und neu aufbauen
        while self._test_zeilen_lyt.count():
            item = self._test_zeilen_lyt.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._test_zeilen.clear()

        aktiv = getattr(self, "_bereiche_aktiv", self._bereiche)

        for bereich in aktiv:
            zeile = _TestZeile(bereich["icon"], bereich["name"])
            self._test_zeilen[bereich["key"]] = zeile
            self._test_zeilen_lyt.addWidget(zeile)

        self._progress_gesamt.setValue(0)
        self._lbl_test_header.setText("Tests laufen …")
        self._btn_abbrechen.setEnabled(True)
        self._btn_weiter.setVisible(False)

        self._runner = AssessmentRunner(
            services=self._services,
            aktive_bereiche=aktiv,
            klient_name=self._klient,
            score_repo=self._score_repo,
        )
        self._runner.test_gestartet.connect(self._on_test_gestartet)
        self._runner.test_fortschritt.connect(self._on_test_fortschritt)
        self._runner.test_fertig.connect(self._on_test_fertig)
        self._runner.alle_fertig.connect(self._on_alle_fertig)
        self._runner.fehler.connect(self._on_test_fehler)
        self._runner.start()

    @Slot(str, int, int)
    def _on_test_gestartet(self, name: str, index: int, gesamt: int) -> None:
        """Markiert den gestarteten Test als laufend.

        Args:
            name: Bereich-Anzeigename.
            index: 0-based Index.
            gesamt: Gesamtzahl Tests.
        """
        zeile = self._test_zeilen.get(self._key_fuer_name(name))
        if zeile:
            zeile.setze_laufend()
        pct = int(index / gesamt * 100)
        self._progress_gesamt.setValue(pct)
        self._lbl_restzeit.setText(f"Test {index + 1} von {gesamt}: {name}")

    @Slot(str, int)
    def _on_test_fortschritt(self, name: str, prozent: int) -> None:
        """Aktualisiert Fortschrittsbalken einer Test-Zeile.

        Args:
            name: Bereich-Anzeigename.
            prozent: 0–100.
        """
        zeile = self._test_zeilen.get(self._key_fuer_name(name))
        if zeile:
            zeile.setze_fortschritt(prozent)

    @Slot(str, float, list)
    def _on_test_fertig(self, name: str, score: float, befunde: list) -> None:
        """Markiert Test als abgeschlossen.

        Args:
            name: Bereich-Anzeigename.
            score: Erreicher Score 0–100.
            befunde: Liste von Befund-Strings.
        """
        zeile = self._test_zeilen.get(self._key_fuer_name(name))
        if zeile:
            zeile.setze_fertig(score)

    @Slot(str, str)
    def _on_test_fehler(self, name: str, meldung: str) -> None:
        """Markiert fehlgeschlagenen Test.

        Args:
            name: Bereich-Anzeigename.
            meldung: Fehlermeldung.
        """
        zeile = self._test_zeilen.get(self._key_fuer_name(name))
        if zeile:
            zeile.setze_fehler()
        self._lbl_restzeit.setText(f"[WARN] Fehler bei '{name}': {meldung[:60]}")

    @Slot(object)
    def _on_alle_fertig(self, score: SecurityScore) -> None:
        """Verarbeitet das fertige Assessment-Ergebnis.

        Args:
            score: Berechneter SecurityScore.
        """
        self._ergebnis = score
        self._progress_gesamt.setValue(100)
        self._lbl_test_header.setText("Alle Tests abgeschlossen")
        self._lbl_restzeit.setText("")

        # Zur Ergebnis-Ansicht wechseln
        self._zeige_schritt(3)

    def _key_fuer_name(self, name: str) -> str:
        """Sucht den Bereich-Key für einen Anzeigenamen.

        Args:
            name: Anzeigename.

        Returns:
            Bereich-Key oder leerer String.
        """
        for b in TESTBEREICHE:
            if b["name"] == name:
                return b["key"]
        return ""

    # ------------------------------------------------------------------
    # Schritt 4: Ergebnis anzeigen
    # ------------------------------------------------------------------

    def _zeige_ergebnis(self, score: SecurityScore) -> None:
        """Füllt die Ergebnis-Ansicht mit dem berechneten Score.

        Args:
            score: Berechneter SecurityScore.
        """
        c = theme.get()
        farbe = _GRADE_COLORS.get(score.grade, theme.SEVERITY_SIGNAL_INFO)

        # Score-Box
        self._lbl_score_zahl.setText(f"{score.overall_score:.0f}")
        self._lbl_score_zahl.setStyleSheet(
            f"font-size: 28px; font-weight: bold; color: {farbe}; border: none;"
        )
        self._score_box.setStyleSheet(
            f"background-color: {c.BG_INPUT}; border: 2px solid {farbe};"
            f" border-radius: 8px;"
        )

        # Note
        self._lbl_note.setText(f"Note: {score.grade}")
        self._lbl_note.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {farbe};"
        )
        self._lbl_note_text.setText(_GRADE_TEXT.get(score.grade, ""))

        # Komponenten
        while self._ergebnis_lyt.count():
            item = self._ergebnis_lyt.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for comp in score.components:
            row_widget = QWidget()
            row_lyt = QHBoxLayout(row_widget)
            row_lyt.setContentsMargins(0, 2, 0, 2)
            row_lyt.setSpacing(8)

            comp_farbe = _GRADE_COLORS.get(
                score_to_grade(comp.score), theme.SEVERITY_SIGNAL_INFO
            )

            name_lbl = QLabel(comp.name)
            name_lbl.setFixedWidth(160)
            name_lbl.setStyleSheet(f"color: {c.TEXT_MAIN}; font-size: 12px;")
            row_lyt.addWidget(name_lbl)

            score_lbl = QLabel(f"{comp.score:.0f}/100")
            score_lbl.setFixedWidth(60)
            score_lbl.setStyleSheet(
                f"color: {comp_farbe}; font-size: 12px; font-weight: bold;"
            )
            row_lyt.addWidget(score_lbl)

            # Befund-Kurzinfo
            befund_parts = []
            if comp.findings_critical:
                befund_parts.append(f"KRIT: {comp.findings_critical}")
            if comp.findings_high:
                befund_parts.append(f"HOCH: {comp.findings_high}")
            if comp.findings_medium:
                befund_parts.append(f"MITTEL: {comp.findings_medium}")

            befund_txt = "  ".join(befund_parts) if befund_parts else "Keine Befunde"
            befund_lbl = QLabel(befund_txt)
            befund_lbl.setStyleSheet(f"color: {c.TEXT_DIM}; font-size: 11px;")
            row_lyt.addWidget(befund_lbl, stretch=1)

            self._ergebnis_lyt.addWidget(row_widget)

        self._ergebnis_lyt.addStretch()

        # Zusammenfassung
        total_crit = sum(c.findings_critical for c in score.components)
        total_high = sum(c.findings_high for c in score.components)
        total_med = sum(c.findings_medium for c in score.components)
        teile = []
        if total_crit:
            teile.append(f"KRIT: {total_crit} kritisch")
        if total_high:
            teile.append(f"HOCH: {total_high} hoch")
        if total_med:
            teile.append(f"MITTEL: {total_med} mittel")
        if not teile:
            teile.append("Keine kritischen Findings")
        self._lbl_zusammenfassung.setText("  |  ".join(teile))

    # ------------------------------------------------------------------
    # Schritt 5: Report
    # ------------------------------------------------------------------

    def _zeige_report_info(self, score: SecurityScore) -> None:
        """Füllt die Abschluss-Report-Ansicht.

        Args:
            score: Berechneter SecurityScore.
        """
        farbe = _GRADE_COLORS.get(score.grade, theme.SEVERITY_SIGNAL_INFO)
        self._lbl_report_info.setText(
            f"Score: <b style='color:{farbe}'>{score.overall_score:.0f}/100 ({score.grade})</b><br>"
            f"System: {score.target_name}<br>"
            f"Datum: {date.today().strftime('%d.%m.%Y')}"
        )
        self._lbl_report_info.setTextFormat(Qt.TextFormat.RichText)

        if self._score_repo:
            self._lbl_gespeichert.setText("Score wurde gespeichert.")
            self._lbl_gespeichert.setStyleSheet(
                f"color: {theme.get().SUCCESS}; font-size: 11px;"
            )
        else:
            self._lbl_gespeichert.setText(
                "ℹ  Kein Repository konfiguriert — Score nicht gespeichert."
            )

    @Slot()
    def _on_pdf_export(self) -> None:
        """Exportiert das Ergebnis als PDF-Report."""
        if not self._ergebnis:
            return

        default_name = (
            f"Security_Report_{self._ergebnis.target_name}_{date.today()}.pdf"
        )
        pfad, _ = QFileDialog.getSaveFileName(
            self,
            "Security-Report speichern",
            default_name,
            "PDF-Dateien (*.pdf)",
        )
        if not pfad:
            return

        try:
            from tools.security_scoring.application.scoring_service import (  # noqa: PLC0415
                generate_security_report_pdf,
            )

            generate_security_report_pdf(self._ergebnis, pfad)
            FinlaiSuccessDialog(
                title="Export erfolgreich",
                message="Report gespeichert:",
                file_path=str(pfad),
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ImportError, ValueError) as exc:
            FinlaiInfoDialog(
                title="Export fehlgeschlagen",
                message=f"PDF konnte nicht erstellt werden:\n{exc}",
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()

    @Slot()
    def _on_clipboard_kopieren(self) -> None:
        """Kopiert die Ergebnis-Zusammenfassung in die Zwischenablage."""
        if not self._ergebnis:
            return

        zeilen = [
            f"Security Assessment — {self._ergebnis.target_name}",
            f"Datum: {date.today().strftime('%d.%m.%Y')}",
            f"Gesamt-Score: {self._ergebnis.overall_score:.0f}/100 (Note {self._ergebnis.grade})",
            "",
        ]
        for comp in self._ergebnis.components:
            zeilen.append(
                f"  {comp.name}: {comp.score:.0f}/100"
                + (
                    f" — {comp.findings_critical} Krit."
                    if comp.findings_critical
                    else ""
                )
                + (f" {comp.findings_high} Hoch" if comp.findings_high else "")
            )

        QApplication.clipboard().setText("\n".join(zeilen))
        FinlaiSuccessDialog(
            title="Kopiert",
            message="Ergebnis wurde in die Zwischenablage kopiert.",
            parent=self,
        ).exec()
