"""
filter_panel — Filter-Panel fuer den CSAF Advisory-Monitor.

Sprint 6 Phase 2b: Zweiter Panel-Extract aus dem
``CsafAdvisorWidget``-God-Class-Refactor. Drei Filter-Sektionen:

* **Schweregrad** -- 4 Checkboxen (Kritisch/Hoch/Mittel/Niedrig).
  Default: Kritisch + Hoch + Mittel aktiv, Niedrig aus.
* **Zeitraum** -- 4 Radios (7/30/90 Tage, Alle). Default: 30 Tage.
* **Treffer** -- 1 Checkbox "Nur Matches".

Public-API:

* ``get_allowed_severities -> set[str]``
* ``get_only_matches -> bool``
* ``get_days -> int | None`` (None = "Alle")

Signal:

* ``filters_changed`` -- emittiert bei jeder Aenderung. Das
  Hauptwidget reagiert mit Service-Refetch + Liste-Refresh.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.help.help_registry import HelpRegistry
from core.help.help_tooltip import HelpButton


class FilterPanel(QScrollArea):
    """Scrollbarer Filter-Bereich fuer den CSAF Advisory-Monitor.

    Erbt von QScrollArea -- der innere Panel-Container ist auf 200px
    Breite fixiert; scroll-Vertical kommt automatisch wenn der Inhalt
    laenger als die Hoehe ist.
    """

    filters_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialisiert das Filter-Panel.

        Args:
            parent: Optionales Eltern-Widget.
        """
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        """Erstellt die UI-Sektionen Schweregrad/Zeitraum/Treffer."""
        t = theme.get()
        panel = QWidget()
        panel.setFixedWidth(200)
        panel.setStyleSheet(
            f"background-color: {t.CARD_BG}; border-radius: 6px;"
            f" border: 1px solid {t.BORDER};"
        )

        self.setWidget(panel)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setStyleSheet("border: none;")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # Severity-Filter
        sev_group = QGroupBox("Schweregrad")
        sev_group.setStyleSheet(
            f"QGroupBox {{ color: {t.TEXT_MAIN}; font-size: 12px; font-weight: bold;"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; margin-top: 8px; }}"
            f"QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}"
        )
        sev_layout = QVBoxLayout(sev_group)
        sev_layout.setSpacing(4)
        _tip_sev = self._help_tip("filter_severity")
        if _tip_sev:
            row_with_help = QHBoxLayout()
            row_with_help.addWidget(sev_group)
            row_with_help.addWidget(HelpButton(_tip_sev), 0, Qt.AlignmentFlag.AlignTop)
            layout.addLayout(row_with_help)
        else:
            layout.addWidget(sev_group)

        self._chk_critical = QCheckBox("Kritisch")
        self._chk_critical.setChecked(True)
        self._chk_high = QCheckBox("Hoch")
        self._chk_high.setChecked(True)
        self._chk_medium = QCheckBox("Mittel")
        self._chk_medium.setChecked(True)
        self._chk_low = QCheckBox("Niedrig")
        self._chk_low.setChecked(False)

        for chk in (
            self._chk_critical,
            self._chk_high,
            self._chk_medium,
            self._chk_low,
        ):
            chk.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 12px;")
            chk.stateChanged.connect(self.filters_changed)
            sev_layout.addWidget(chk)

        # Zeitraum-Filter
        time_group = QGroupBox("Zeitraum")
        time_group.setStyleSheet(sev_group.styleSheet())
        time_layout = QVBoxLayout(time_group)
        time_layout.setSpacing(4)

        self._rb_7 = QRadioButton("7 Tage")
        self._rb_30 = QRadioButton("30 Tage")
        self._rb_30.setChecked(True)
        self._rb_90 = QRadioButton("90 Tage")
        self._rb_all = QRadioButton("Alle")

        for rb in (self._rb_7, self._rb_30, self._rb_90, self._rb_all):
            rb.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 12px;")
            rb.toggled.connect(self.filters_changed)
            time_layout.addWidget(rb)

        layout.addWidget(time_group)

        # Matches-Filter
        match_group = QGroupBox("Treffer")
        match_group.setStyleSheet(sev_group.styleSheet())
        match_layout = QVBoxLayout(match_group)

        self._chk_only_matches = QCheckBox("Nur Matches")
        self._chk_only_matches.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 12px;")
        self._chk_only_matches.stateChanged.connect(self.filters_changed)
        match_layout.addWidget(self._chk_only_matches)

        layout.addWidget(match_group)
        layout.addStretch()

    # ------------------------------------------------------------------
    # Public API -- wird vom Hauptwidget gelesen wenn filters_changed feuert
    # ------------------------------------------------------------------

    def get_allowed_severities(self) -> set[str]:
        """Gibt die aktivierten Schweregrade zurueck (lowercase Strings)."""
        allowed: set[str] = set()
        if self._chk_critical.isChecked():
            allowed.add("critical")
        if self._chk_high.isChecked():
            allowed.add("high")
        if self._chk_medium.isChecked():
            allowed.add("medium")
        if self._chk_low.isChecked():
            allowed.add("low")
        return allowed

    def get_only_matches(self) -> bool:
        """True wenn die "Nur Matches"-Checkbox aktiv ist."""
        return self._chk_only_matches.isChecked()

    def get_days(self) -> int | None:
        """Gibt den Zeitraum-Filter in Tagen zurueck.

        Returns:
            7/30/90 fuer die jeweiligen Radios, ``None`` fuer "Alle".
        """
        if self._rb_7.isChecked():
            return 7
        if self._rb_30.isChecked():
            return 30
        if self._rb_90.isChecked():
            return 90
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _help_tip(key: str) -> str:
        """Holt einen HelpTooltip fuer das CSAF-Advisor-Tool.

        Args:
            key: Tooltip-Key (z. B. ``"filter_severity"``).

        Returns:
            Tooltip-Text oder leerer String wenn nicht registriert.
        """
        hc = HelpRegistry.get("csaf_advisor")
        return hc.tooltips.get(key, "") if hc else ""
