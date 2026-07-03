"""measurement_gate_banner — Soft-"N offen"-Banner fuer den Mess-zuerst-Flow.

 Phase 4 / D4 (Soft-Gate): zeigt im Security-Scoring-Dashboard an, dass
noch Haertungs-Checks mit Adminrechten nachmessbar sind. Das Banner blockiert
nichts (Soft-Gate) — es macht die offenen Posten sichtbar und bietet zwei
Aktionen: jetzt mit Admin messen ODER bewusst verzichten. Bleibt es ungenutzt,
draengt die niedrige Coverage ohnehin die Ampel (Stage-Guard, Phase 3).

Sichtbar NUR wenn ``disposition.gate_open`` (offene, nachmessbare Checks) — sonst
versteckt (kein Dauer-Rauschen). Pure Text-/Sichtbarkeits-Logik ist in
Modul-Funktionen ausgelagert (testbar ohne Qt-Instanz), analog zu
:mod:`tools.awareness_tracker.gui.renewal_banner`.

Schichtzugehoerigkeit: gui/ — darf application/, domain/ + core/ importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from core import theme
from core.icons import ICON_SIZE_LG, Icons, get_icon

if TYPE_CHECKING:
    from tools.system_scanner.domain.entities import MeasurementDisposition


class GateBannerState(StrEnum):
    """Transienter/terminaler Zustand des Mess-Banners (D6 Phase 2).

    ``OPEN`` wird ueber:meth:`MeasurementGateBanner.update_from` aus der
    Disposition gesetzt (oder versteckt); die uebrigen Zustaende ueber
:meth:`MeasurementGateBanner.set_state` waehrend/nach einem Recheck.
    """

    RUNNING = "running"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


#: Rahmenfarbe + Icon je Zustand (Material Symbols).
_STATE_STYLE: dict[GateBannerState, tuple[str, Icons]] = {
    GateBannerState.RUNNING: (theme.ACCENT, Icons.HOURGLASS),
    GateBannerState.REJECTED: (theme.ERROR, Icons.ERROR),
    GateBannerState.TIMEOUT: (theme.ERROR, Icons.PENDING),
}


class MeasurementGateBanner(QFrame):
    """Soft-Banner fuer offene (nachmessbare) Haertungs-Checks D4).

    Signals:
        measure_clicked: Nutzer will die offenen Checks mit Adminrechten
            nachmessen (-> elevierter Recheck).
        decline_clicked: Nutzer verzichtet bewusst auf die Messung (-> die
            offenen Checks werden als USER_DECLINED markiert).
    """

    measure_clicked = Signal()
    decline_clicked = Signal()

    def __init__(self, parent=None) -> None:  # noqa: ANN001 — QWidget-Subklasse
        super().__init__(parent)
        self.setObjectName("MeasurementGateBanner")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._apply_frame_style(theme.WARNING)
        self._build_ui()
        self.update_from(None)

    def _apply_frame_style(self, border_color: str) -> None:
        """Setzt den Rahmen (id-Selektor, damit die Kind-Buttons die globale
        Kaskade behalten — R23/R26)."""
        self.setStyleSheet(
            f"#MeasurementGateBanner {{"
            f"  background: {theme.BG_INPUT};"
            f"  border: 1px solid {border_color};"
            f"  border-radius: 6px;"
            f"}}"
        )

    def _set_icon(self, icon: Icons, color: str) -> None:
        self._icon_label.setPixmap(
            get_icon(icon, color=color).pixmap(QSize(ICON_SIZE_LG, ICON_SIZE_LG))
        )

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        self._icon_label = QLabel()
        self._icon_label.setObjectName("MeasurementGateBannerIcon")
        self._icon_label.setPixmap(
            get_icon(Icons.SHIELD, color=theme.WARNING).pixmap(
                QSize(ICON_SIZE_LG, ICON_SIZE_LG)
            )
        )
        layout.addWidget(self._icon_label)

        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        self._title_label = QLabel("")
        self._title_label.setObjectName("MeasurementGateBannerTitle")
        text_box.addWidget(self._title_label)
        self._detail_label = QLabel("")
        self._detail_label.setObjectName("MeasurementGateBannerDetail")
        self._detail_label.setWordWrap(True)
        text_box.addWidget(self._detail_label)
        layout.addLayout(text_box, stretch=1)

        self._measure_button = QPushButton("Mit Admin messen")
        self._measure_button.setObjectName("MeasurementGateBannerMeasureButton")
        self._measure_button.clicked.connect(self.measure_clicked.emit)
        layout.addWidget(self._measure_button)

        self._decline_button = QPushButton("Nicht messen")
        self._decline_button.setObjectName("MeasurementGateBannerDeclineButton")
        self._decline_button.clicked.connect(self.decline_clicked.emit)
        layout.addWidget(self._decline_button)

    def update_from(
        self,
        disposition: MeasurementDisposition | None,
        open_labels: list[str] | None = None,
    ) -> None:
        """Aktualisiert Text + Sichtbarkeit aus der Disposition.

        Args:
            disposition: Mess-zuerst-Status aus dem ``HardeningScoreResult``,
                oder ``None`` (dann versteckt).
            open_labels: Namen der offenen (nachmessbaren) Checks fuer die
                Transparenz-Zeile ("Betrifft: …"). ``None`` = nicht anzeigen.
        """
        if not gate_banner_visible(disposition):
            self.setVisible(False)
            return
        self.setVisible(True)
        # OPEN-Erscheinung wiederherstellen (set_state kann sie veraendert haben).
        self._apply_frame_style(theme.WARNING)
        self._set_icon(Icons.SHIELD, theme.WARNING)
        self._title_label.setText(gate_banner_title(disposition))
        self._detail_label.setText(gate_banner_detail(disposition, open_labels))
        self._measure_button.setText("Mit Admin messen")
        self._measure_button.setEnabled(True)
        self._decline_button.setVisible(True)

    def set_state(self, state: GateBannerState, *, reason_text: str = "") -> None:
        """Setzt einen transienten/terminalen Zustand (RUNNING/REJECTED/TIMEOUT).

        Macht den Recheck-Ausgang sichtbar (D6 Phase 2): waehrend der Messung
        deaktivierter Button + Hinweis; bei Fehler/Timeout roter Rahmen, Grund
        und ein "Erneut messen"-Button am selben Anker.

        Args:
            state: Ziel-Zustand.
            reason_text: Bei ``REJECTED`` der lesbare Grund (vom Aufrufer
                gemappt; bewusst generisch, kein Pfad/Exception-Text).
        """
        self.setVisible(True)
        color, icon = _STATE_STYLE[state]
        self._apply_frame_style(color)
        self._set_icon(icon, color)
        self._title_label.setText(gate_state_title(state))
        self._detail_label.setText(gate_state_detail(state, reason_text))
        running = state is GateBannerState.RUNNING
        self._measure_button.setEnabled(not running)
        self._measure_button.setText("Wird gemessen …" if running else "Erneut messen")
        self._decline_button.setVisible(not running)


# ---------------------------------------------------------------------------
# Reine Logik (testbar ohne Qt-Widget-Instanz)
# ---------------------------------------------------------------------------


def gate_banner_visible(disposition: MeasurementDisposition | None) -> bool:
    """True wenn das Banner gezeigt werden soll (offene, nachmessbare Checks)."""
    return disposition is not None and disposition.gate_open


def gate_banner_title(disposition: MeasurementDisposition) -> str:
    """Banner-Ueberschrift mit der Zahl offener Checks (DE-Plural)."""
    n = disposition.open_remeasurable
    wort = "Härtungs-Check" if n == 1 else "Härtungs-Checks"
    return f"{n} {wort} noch nicht gemessen"


def gate_banner_detail(
    disposition: MeasurementDisposition,
    open_labels: list[str] | None = None,
) -> str:
    """Banner-Detailzeile: WAS geprueft wird ("Betrifft: …"), dass es nur mit
    Adminrechten messbar ist, plus Hinweis auf bewusste Verzichte (Transparenz).
    """
    teile = [
        "Nur mit Adminrechten auslesbar — bis dahin ist die Bewertung gedeckelt."
    ]
    if open_labels:
        teile.append("Betrifft: " + ", ".join(open_labels))
    if disposition.opted_out:
        teile.append(
            f"{disposition.opted_out} bereits als nicht gemessen markiert"
        )
    return " · ".join(teile)


def gate_state_title(state: GateBannerState) -> str:
    """Banner-Ueberschrift fuer einen transienten/terminalen Zustand (D6)."""
    return {
        GateBannerState.RUNNING: "Messung läuft …",
        GateBannerState.REJECTED: "Admin-Messung fehlgeschlagen",
        GateBannerState.TIMEOUT: "Keine Rückmeldung erhalten",
    }[state]


def gate_state_detail(state: GateBannerState, reason_text: str = "") -> str:
    """Banner-Detailzeile fuer einen transienten/terminalen Zustand (D6).

    Der Score-bleibt-unveraendert-Hinweis ist Teil der Ehrlichkeit:
    bei Fehler/Timeout wurde NICHT gemessen.
    """
    if state is GateBannerState.RUNNING:
        return (
            "Bitte bestätigen Sie die Windows-Abfrage und lassen Sie das "
            "Fenster geöffnet."
        )
    if state is GateBannerState.TIMEOUT:
        return (
            "Es kam kein Ergebnis innerhalb von 90 Sekunden zurück. Ihr Score "
            "wurde nicht verändert. Bitte versuchen Sie es erneut."
        )
    base = reason_text or "die Messung ist fehlgeschlagen"
    return f"{base[:1].upper()}{base[1:]} — Ihr Score wurde nicht verändert."


__all__ = [
    "GateBannerState",
    "MeasurementGateBanner",
    "gate_banner_detail",
    "gate_banner_title",
    "gate_banner_visible",
    "gate_state_detail",
    "gate_state_title",
]
