"""
hardening_trend_indicator — Trend-Pfeil neben dem Hardening-Score-Gauge (Phase 4d).

Kleines horizontales Widget, das die Differenz zwischen aktuellem und
vorherigem Hardening-Score visualisiert:

* ↑ (gruen) bei steigendem Score
* ↓ (rot) bei fallendem Score
* → (grau) bei (nahezu) gleichem Score

Pflicht-Eingaben werden ueber:meth:`set_trend(previous, current)` gesetzt.
Single-Tenant-OSS — kein Free/Pro-Gating mehr; der Trend
wird immer angezeigt.

Persistenz-Quelle::class:`HardeningScoreRepository.get_last_two_scores`.

Schichtzugehoerigkeit: gui/ — keine Domain-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QWidget,
)

from core import theme

#: Schwellenwert (in Score-Punkten), unter dem ein Score-Delta als
#: "stabil" gilt. Verhindert flackernde Pfeile bei Rundungsrauschen
#: (z. B. 87.4 → 87.6).
_STABLE_THRESHOLD: Final[float] = 0.5

_ARROW_UP = "↑"
_ARROW_DOWN = "↓"
_ARROW_FLAT = "→"

_NO_HISTORY_TEXT = "— kein Vergleich —"


class HardeningTrendIndicator(QWidget):
    """Trend-Pfeil + Delta-Zahl neben dem Hardening-Score-Gauge.

    Public API:

    *:meth:`set_trend(previous, current)` — Aktualisiert Pfeil + Delta.
      ``previous=None`` zeigt den "kein Vergleich"-Zustand (erster
      Scan eines Targets).

    Layout: ``[Pfeil] [Delta-Zahl]`` — ein einziges HBox.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._previous: float | None = None
        self._current: float | None = None

        self.setSizePolicy(
            QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(4)

        self._arrow_label = QLabel(_ARROW_FLAT, self)
        font_arrow = self._arrow_label.font()
        font_arrow.setPointSize(16)
        font_arrow.setBold(True)
        self._arrow_label.setFont(font_arrow)
        self._arrow_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._arrow_label)

        self._delta_label = QLabel("", self)
        font_delta = self._delta_label.font()
        font_delta.setPointSize(11)
        self._delta_label.setFont(font_delta)
        layout.addWidget(self._delta_label)

        self._refresh()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_trend(
        self,
        previous: float | None,
        current: float | None,
    ) -> None:
        """Setzt Vorgaenger + aktuellen Score.

        Args:
            previous: Score des vorletzten Scans (oder ``None`` wenn
                kein Vergleich verfuegbar ist).
            current: Score des juengsten Scans (oder ``None`` wenn noch
                nichts berechnet wurde).
        """
        self._previous = previous
        self._current = current
        self._refresh()

    @property
    def arrow_text(self) -> str:
        """Aktuelles Pfeil-Symbol — fuer Tests."""
        return self._arrow_label.text()

    @property
    def delta_text(self) -> str:
        """Aktueller Delta-Text — fuer Tests."""
        return self._delta_label.text()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._previous is None or self._current is None:
            self._render_no_history()
            return
        delta = self._current - self._previous
        if abs(delta) < _STABLE_THRESHOLD:
            self._render_flat()
        elif delta > 0:
            self._render_up(delta)
        else:
            self._render_down(delta)

    def _render_no_history(self) -> None:
        c = theme.get()
        self._arrow_label.setText(_ARROW_FLAT)
        self._arrow_label.setStyleSheet(f"color: {c.TEXT_DIM};")
        self._delta_label.setText(_NO_HISTORY_TEXT)
        self._delta_label.setStyleSheet(f"color: {c.TEXT_DIM};")
        self.setToolTip(
            "Noch kein Vorgaenger-Score fuer dieses Target."
        )

    def _render_flat(self) -> None:
        c = theme.get()
        self._arrow_label.setText(_ARROW_FLAT)
        self._arrow_label.setStyleSheet(f"color: {c.TEXT_DIM};")
        self._delta_label.setText("± 0")
        self._delta_label.setStyleSheet(f"color: {c.TEXT_DIM};")
        self.setToolTip(
            f"Score stabil bei {self._current:.1f} "
            f"(Vorgaenger {self._previous:.1f})."
        )

    def _render_up(self, delta: float) -> None:
        c = theme.get()
        self._arrow_label.setText(_ARROW_UP)
        self._arrow_label.setStyleSheet(f"color: {c.SUCCESS};")
        self._delta_label.setText(f"+{delta:.1f}")
        self._delta_label.setStyleSheet(f"color: {c.SUCCESS};")
        self.setToolTip(
            f"Score gestiegen: {self._previous:.1f} → {self._current:.1f}"
        )

    def _render_down(self, delta: float) -> None:
        c = theme.get()
        self._arrow_label.setText(_ARROW_DOWN)
        self._arrow_label.setStyleSheet(f"color: {c.DANGER};")
        self._delta_label.setText(f"{delta:.1f}")  # delta ist negativ → "-5.4"
        self._delta_label.setStyleSheet(f"color: {c.DANGER};")
        self.setToolTip(
            f"Score gesunken: {self._previous:.1f} → {self._current:.1f}"
        )
