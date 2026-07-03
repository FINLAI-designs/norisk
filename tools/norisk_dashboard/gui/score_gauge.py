"""score_gauge — Halbkreis-Tachometer für den Security-Score (Sprint S3b).

Visualisiert ``ScoreSnapshot.current`` als oberen Halbkreis-Bogen mit
3 Farbzonen, exakt passend zu den ``cve_exposure``-Statusschwellen
(Patrick-Entscheidung 2026-04-29):

  - ``>= 80`` → ``OK`` — grün
  - ``60..79`` → ``Warnung`` — orange
  - ``< 60`` → ``Kritisch`` — rot
  - ``None`` → ``—`` — dim (noch kein Score)

Hover-Tooltip listet die einzelnen:class:`ScoreComponent`-Werte auf;
Klick emittiert ein parameterloses ``clicked``-Signal, das die
:class:`ScoreSection` zur Score-Aufschlüsselungs-Sektion weiterleiten
kann.

QPainter-Pattern bewusst angelehnt an
``tools/security_scoring/gui/scoring_dashboard_widget.py:_ScoreRingWidget``
(volle Kreis-Variante) — wir bauen daraus eine Halbkreis-Version mit
3-Zonen-Farblogik.

Schichtzugehörigkeit: gui/ — keine Domain-Logik, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme
from tools.security_scoring.domain.cve_exposure import (
    _STATUS_OK_THRESHOLD,
    _STATUS_WARN_THRESHOLD,
)
from tools.security_scoring.domain.models import ScoreComponent

# QPainter rechnet in 1/16-Grad. Wir definieren Konstanten in normalen
# Grad-Einheiten und multiplizieren beim drawArc-Call mit ``_DEG``.
_DEG = 16
_HALF_CIRCLE_START_DEG = 180  # 9-Uhr-Position
_HALF_CIRCLE_SPAN_DEG = 180  # Bogen von 180° (links) ueber 90° (oben) zu 0° (rechts)

# Pen-Breite in Pixeln. Bewusst so dick, dass die Farbzone auch auf
# kleinen Bildschirmen sofort lesbar ist.
_RING_WIDTH = 14


class ScoreGauge(QWidget):
    """Halbkreis-Tachometer-Widget für den Security-Score.

    Args:
        parent: Optionales Eltern-Widget.

    Signals:
        clicked: Emittiert beim Linksklick. Konsumenten (typisch
:class:`ScoreSection`) leiten das an die Score-Aufschlüsselungs-
            Sektion weiter.

    Public API:
        set_data(score, breakdown):
            Aktualisiert den dargestellten Score sowie den Tooltip-Inhalt.
    """

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: float | None = None
        self._breakdown: list[ScoreComponent] = []
        self.setFixedSize(QSize(220, 140))
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_tooltip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_data(
        self,
        score: float | None,
        breakdown: list[ScoreComponent] | None = None,
    ) -> None:
        """Setzt Score-Wert und (optional) Komponenten-Aufschlüsselung neu.

        Triggert:meth:`update`, sodass das Widget neu gezeichnet wird.

        Args:
            score: Aktueller Security-Score (0..100) oder ``None`` für
                den "noch kein Score"-Zustand.
            breakdown: Liste von:class:`ScoreComponent` für den Hover-
                Tooltip. ``None`` oder leere Liste blendet die Detail-
                Zeilen aus und zeigt nur den Status-Hinweis.
        """
        self._score = score
        self._breakdown = list(breakdown) if breakdown else []
        self._refresh_tooltip()
        self.update()

    # ------------------------------------------------------------------
    # Painter
    # ------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: D401, N802 -- Qt-Override
        """Zeichnet Hintergrund-Halbkreis, Wert-Bogen, Score-Zahl, Status-Label."""
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
        # Bounding-Box für die Halbkreis-Bahn — Höhe ist doppelt so
        # gross, weil wir nur die obere Hälfte zeichnen und das Rect
        # selbst einen vollen Kreis aufspannt.
        rect = QRectF(
            margin,
            margin,
            w - 2 * margin,
            (h - margin) * 2 - margin,
        )

        # Hintergrund-Bogen
        pen_bg = QPen(QColor(t.BORDER))
        pen_bg.setWidth(_RING_WIDTH)
        pen_bg.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen_bg)
        painter.drawArc(
            rect,
            _HALF_CIRCLE_START_DEG * _DEG,
            -_HALF_CIRCLE_SPAN_DEG * _DEG,  # negativ = im Uhrzeigersinn
        )

        # Wert-Bogen (nur wenn Score vorhanden)
        if self._score is not None:
            color = _color_for_score(self._score, t)
            pen_score = QPen(QColor(color))
            pen_score.setWidth(_RING_WIDTH)
            pen_score.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen_score)
            span = -int(
                max(0.0, min(self._score, 100.0))
                / 100.0
                * _HALF_CIRCLE_SPAN_DEG
                * _DEG
            )
            painter.drawArc(rect, _HALF_CIRCLE_START_DEG * _DEG, span)

        # Score-Zahl (zentriert in der Halbkreis-Mitte)
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

        # Status-Label (klein, dezent unter der Zahl)
        painter.setPen(QColor(t.TEXT_DIM))
        font_status = QFont()
        font_status.setPointSize(9)
        painter.setFont(font_status)
        painter.drawText(
            QRectF(0, h * 0.72, w, h * 0.20),
            Qt.AlignmentFlag.AlignCenter,
            _status_label(self._score),
        )

    # ------------------------------------------------------------------
    # Tooltip + Click
    # ------------------------------------------------------------------

    def _refresh_tooltip(self) -> None:
        """Baut den Tooltip-Text aus aktuellem Score + Komponenten neu."""
        if self._score is None:
            self.setToolTip(
                "Noch kein Security-Score berechnet.\n"
                "Starte einen Scan, um den Score zu sehen."
            )
            return
        lines: list[str] = [
            f"Security-Score: {self._score:.1f} — {_status_label(self._score)}",
            "",
        ]
        if not self._breakdown:
            lines.append("(Noch keine Komponenten-Daten verfügbar)")
        else:
            lines.append("Komponenten:")
            for comp in self._breakdown:
                marker = "●" if comp.data_available else "○"
                value = (
                    f"{comp.score:.0f}" if comp.data_available else "—"
                )
                lines.append(
                    f"  {marker} {comp.name}: {value}"
                )
        self.setToolTip("\n".join(lines))

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802 -- Qt-Override
        """Linksklick → ``clicked``-Signal."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _color_for_score(score: float, t) -> str:  # noqa: ANN001 -- ThemeColors intern
    """Mappt einen Score auf eine Theme-Farbe — 3 Zonen per Patrick-Entscheidung.

    Schwellen exakt aus:mod:`cve_exposure`:
      - ``>= 80`` (``_STATUS_OK_THRESHOLD``) → ``SUCCESS``
      - ``>= 60`` (``_STATUS_WARN_THRESHOLD``) → ``WARNING_ORANGE``
      - ``< 60`` → ``DANGER``
    """
    if score >= _STATUS_OK_THRESHOLD:
        return t.SUCCESS
    if score >= _STATUS_WARN_THRESHOLD:
        return theme.WARNING_ORANGE
    return t.DANGER


def _status_label(score: float | None) -> str:
    """Liefert den Status-Text passend zum Score (analog ``cve_exposure``)."""
    if score is None:
        return "Keine Daten"
    if score >= _STATUS_OK_THRESHOLD:
        return "OK"
    if score >= _STATUS_WARN_THRESHOLD:
        return "Warnung"
    return "Kritisch"
