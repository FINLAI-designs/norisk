"""
human_risk_gauge — 4-Stufen-Halbkreis-Gauge fuer den Human-Risk-Score.

Visualisiert einen Score 0..100 (hoeher = besser) als oberen Halbkreis-Bogen
mit vier Ampel-Stufen (Stark / Solide / Ausbaufaehig / Kritisch). Farben
kommen aus:mod:`core.theme` (Modul-Konstanten ``SCORE_STAGE_*`` — R1-konform,
kein hardcoded Hex).

Bewusst self-contained im awareness_tracker (kein Cross-Tool-Import auf den
HardeningScoreGauge): das QPainter-Muster (Halbkreis, gedimmte Hintergrund-
Sektoren, Wert-Bogen) ist daran angelehnt, das Band-Mapping ist lokal.

Schichtzugehoerigkeit: gui/ — keine DB, keine application-Logik.

Author: Patrick Riederich
Version: 1.0 (IA-Welle 2)
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme
from tools.awareness_tracker.domain.human_risk_score import (
    RiskBand,
    band_for_score,
)

# QPainter rechnet in 1/16-Grad.
_DEG = 16
_HALF_CIRCLE_START_DEG = 180  # 9-Uhr-Position
_HALF_CIRCLE_SPAN_DEG = 180

_RING_WIDTH = 14
_DEFAULT_SIZE = QSize(220, 140)

# Band -> Theme-Farb-Konstante (core.theme, R1-konform).
_BAND_COLORS: dict[RiskBand, str] = {
    RiskBand.SECURE: theme.SCORE_STAGE_SECURE,
    RiskBand.MODERATE: theme.SCORE_STAGE_MODERATE,
    RiskBand.AT_RISK: theme.SCORE_STAGE_AT_RISK,
    RiskBand.CRITICAL: theme.SCORE_STAGE_CRITICAL,
}

# Hintergrund-Sektoren: (Band, min_score, max_score) — deckt 0..100 luecken-frei.
_BAND_RANGES: tuple[tuple[RiskBand, int, int], ...] = (
    (RiskBand.CRITICAL, 0, 39),
    (RiskBand.AT_RISK, 40, 64),
    (RiskBand.MODERATE, 65, 84),
    (RiskBand.SECURE, 85, 100),
)


class HumanRiskGauge(QWidget):
    """4-Stufen-Halbkreis-Tachometer fuer den Human-Risk-Score.

    Public API:
        *:meth:`set_score(score, band=None)` — Score 0..100; ``None`` zeigt
          den "noch keine Daten"-Zustand. Band wird via
:func:`band_for_score` abgeleitet, wenn nicht explizit gesetzt.

    Signals:
        clicked: Linksklick (z. B. Drill-Down auf die Detail-Tabs).
    """

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: float | None = None
        self._band: RiskBand | None = None
        self.setFixedSize(_DEFAULT_SIZE)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_tooltip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_score(self, score: float | None, band: RiskBand | None = None) -> None:
        """Setzt Score + Band.

        Args:
            score: Score 0..100 oder ``None`` fuer "keine Daten".
            band: Optional. Wenn ``None``, wird das Band aus dem Score
                abgeleitet (nur wenn Score nicht None).
        """
        if score is None:
            self._score = None
            self._band = None
        else:
            self._score = float(score)
            self._band = band if band is not None else band_for_score(score)
        self._refresh_tooltip()
        self.update()

    @property
    def current_score(self) -> float | None:
        """Aktuell angezeigter Score (read-only, fuer Tests)."""
        return self._score

    @property
    def current_band(self) -> RiskBand | None:
        """Aktuell aktives Band (read-only, fuer Tests)."""
        return self._band

    # ------------------------------------------------------------------
    # Painter
    # ------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 — Qt-Override
        """Zeichnet Hintergrund-Sektoren, Wert-Bogen, Score-Zahl, Band-Label."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        try:
            self._paint(painter)
        finally:
            painter.end()

    def _paint(self, painter: QPainter) -> None:
        t = theme.get()
        w, h = self.width(), self.height()
        margin = _RING_WIDTH
        rect = QRectF(
            margin,
            margin,
            w - 2 * margin,
            (h - margin) * 2 - margin,
        )

        self._paint_band_backgrounds(painter, rect)

        if self._score is not None:
            pen_score = QPen(QColor(_band_color(self._band)))
            pen_score.setWidth(_RING_WIDTH)
            pen_score.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen_score)
            span = -int(
                max(0.0, min(self._score, 100.0)) / 100.0 * _HALF_CIRCLE_SPAN_DEG * _DEG
            )
            painter.drawArc(rect, _HALF_CIRCLE_START_DEG * _DEG, span)

        # Score-Zahl (zentriert).
        painter.setPen(QColor(t.TEXT_MAIN))
        font_score = QFont()
        font_score.setPointSize(28)
        font_score.setBold(True)
        painter.setFont(font_score)
        text = "—" if self._score is None else f"{self._score:.0f}"
        painter.drawText(
            QRectF(0, h * 0.30, w, h * 0.40),
            Qt.AlignmentFlag.AlignCenter,
            text,
        )

        # Band-Label (klein, dezent).
        painter.setPen(QColor(t.TEXT_DIM))
        font_label = QFont()
        font_label.setPointSize(9)
        painter.setFont(font_label)
        painter.drawText(
            QRectF(0, h * 0.72, w, h * 0.20),
            Qt.AlignmentFlag.AlignCenter,
            _band_label(self._band),
        )

    def _paint_band_backgrounds(self, painter: QPainter, rect: QRectF) -> None:
        """Zeichnet die vier gedimmten Band-Sektoren ueber den Halbkreis."""
        for band, min_score, max_score in _BAND_RANGES:
            color = QColor(_band_color(band))
            color.setAlpha(90)  # subtil, aber sichtbar
            pen = QPen(color)
            pen.setWidth(_RING_WIDTH)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            start_pct = min_score / 100.0
            # +1 weil max_score inklusiv ist; oben auf 100 deckeln, sonst
            # liefe das SECURE-Band (max=100) auf 101 % und der Sektor ragte
            # ~1,8 Grad ueber den Halbkreis hinaus (Review P2).
            end_pct = min(max_score + 1, 100) / 100.0
            start_angle = int(
                (_HALF_CIRCLE_START_DEG - start_pct * _HALF_CIRCLE_SPAN_DEG) * _DEG
            )
            span_angle = -int((end_pct - start_pct) * _HALF_CIRCLE_SPAN_DEG * _DEG)
            painter.drawArc(rect, start_angle, span_angle)

    # ------------------------------------------------------------------
    # Tooltip + Click
    # ------------------------------------------------------------------

    def _refresh_tooltip(self) -> None:
        """Baut den Tooltip aus Score + Band neu."""
        if self._score is None or self._band is None:
            self.setToolTip(
                "Noch kein Human-Risk-Score.\n"
                "Erfasse Mitarbeiter, Schulungen und Phishing-Simulationen."
            )
            return
        self.setToolTip(
            f"Human-Risk-Score: {self._score:.0f} — {self._band.label}\n"
            "Hoeher = besser. Gewichtung: Melderate 40 %, "
            "Klick-Vermeidung 35 %, Schulung 25 %."
        )

    def mousePressEvent(self, event) -> None:  # noqa: N802 — Qt-Override
        """Linksklick -> ``clicked``-Signal."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _band_color(band: RiskBand | None) -> str:
    """Hex-Farbe eines Bands (Fallback: neutraler Border-Ton)."""
    if band is None:
        return theme.get().BORDER
    return _BAND_COLORS.get(band, theme.get().BORDER)


def _band_label(band: RiskBand | None) -> str:
    """Label fuer das untere Gauge-Label."""
    if band is None:
        return "Keine Daten"
    return band.label
