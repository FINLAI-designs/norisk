"""
hardening_score_gauge — 4-Stage-Halbkreis-Gauge fuer den Hardening-Score (Phase 4b).

Visualisiert ein:class:`HardeningScoreResult` als oberen Halbkreis-Bogen
mit den 4 Ampel-Stufen (Secure / Moderate / At Risk / Critical) aus
:mod:`tools.security_scoring.domain.hardening_stages`. Farben kommen aus
:data:`core.theme.SCORE_STAGE_COLORS` (R1-konform — kein hardcoded Hex).

Abgrenzung zur bestehenden:class:`tools.norisk_dashboard.gui.score_gauge.ScoreGauge`:
diese ist 3-Zonen-basiert (OK/Warnung/Kritisch) und an die
``cve_exposure``-Schwellen gekoppelt. Der hier neue
:class:`HardeningScoreGauge` ist 4-Stage-basiert v2 §3) und
konsumiert das vollstaendige:class:`HardeningScoreResult`. Verwendet im
Security-Scoring-Tab; das NoRisk-Cockpit zeigt den Hardening-Score seit
 Phase 4) als beschriftete Kachel im ``SecurityCockpitBand``
(kein Gauge mehr) — der frühere Hero-Gauge entfiel.

QPainter-Pattern bewusst angelehnt an
:class:`tools.norisk_dashboard.gui.score_gauge.ScoreGauge` (Halbkreis-
Form, Pen-Konstanten, drawArc-Konvention).

Schichtzugehoerigkeit: gui/ — keine Domain-Logik, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from core import theme
from tools.security_scoring.domain.hardening_stages import (
    SCORE_STAGES,
    ScoreStage,
    score_to_stage,
)

if TYPE_CHECKING:
    from tools.security_scoring.domain.hardening_score import HardeningScoreResult

# QPainter rechnet in 1/16-Grad. Konstanten in normalen Grad-Einheiten,
# wir multiplizieren beim drawArc-Call mit ``_DEG``.
_DEG = 16
_HALF_CIRCLE_START_DEG = 180  # 9-Uhr-Position
_HALF_CIRCLE_SPAN_DEG = 180   # Bogen 180° (links) → 90° (oben) → 0° (rechts)

#: Pen-Breite in Pixeln. Bewusst dick, damit die Stage-Farbe auch auf
#: kleinen Displays sofort erkennbar ist.
_RING_WIDTH = 14

#: Default-Widget-Groesse — identisch zur bestehenden ScoreGauge (gemeinsame
#: Halbkreis-Geometrie/QPainter-Konvention).
_DEFAULT_SIZE = QSize(220, 140)


class HardeningScoreGauge(QWidget):
    """4-Stage-Halbkreis-Tachometer fuer den Hardening-Score.

    Public API:

    *:meth:`set_result(result)` — Aktualisiert Score + Stage. ``None``
      zeigt den "noch kein Score"-Zustand.
    *:meth:`set_score(score, stage=None)` — Convenience-API ohne
      ``HardeningScoreResult`` (Stage wird via:func:`score_to_stage`
      abgeleitet, wenn nicht explizit gesetzt).

    Signals:
        clicked: Linksklick. Konsumenten leiten das z. B. an eine
            Drill-Down-Sektion mit Kategorie-Breakdown (Phase 4c).
    """

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: float | None = None
        self._stage: ScoreStage | None = None
        self.setFixedSize(_DEFAULT_SIZE)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_tooltip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_result(self, result: HardeningScoreResult | None) -> None:
        """Setzt Score + Stage aus einem vollstaendigen Ergebnis.

        Args:
            result: Ergebnis aus
:func:`tools.security_scoring.domain.hardening_score.compute_hardening_score`
                oder ``None`` fuer den "noch kein Score"-Zustand.
        """
        if result is None:
            self._score = None
            self._stage = None
        else:
            self._score = float(result.overall_score)
            self._stage = result.stage
        self._refresh_tooltip()
        self.update()

    def set_score(
        self,
        score: float | None,
        stage: ScoreStage | None = None,
    ) -> None:
        """Convenience-API ohne ``HardeningScoreResult``.

        Args:
            score: Score 0-100 oder ``None``.
            stage: Wenn ``None``, wird die Stage via:func:`score_to_stage`
                aus dem Score abgeleitet (nur wenn Score nicht None).
        """
        if score is None:
            self._score = None
            self._stage = None
        else:
            self._score = float(score)
            self._stage = stage if stage is not None else score_to_stage(score)
        self._refresh_tooltip()
        self.update()

    @property
    def current_score(self) -> float | None:
        """Aktuell angezeigter Score (oder ``None``). Read-only — fuer Tests."""
        return self._score

    @property
    def current_stage(self) -> ScoreStage | None:
        """Aktuell aktive Stage (oder ``None``). Read-only — fuer Tests."""
        return self._stage

    # ------------------------------------------------------------------
    # Painter
    # ------------------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: D401, N802 — Qt-Override
        """Zeichnet Hintergrund-Halbkreis, Wert-Bogen, Score-Zahl, Stage-Label."""
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
        # Bounding-Box: Hoehe ist doppelt so gross, weil wir nur den
        # oberen Halbkreis zeichnen und das Rect einen vollen Kreis
        # aufspannt.
        rect = QRectF(
            margin,
            margin,
            w - 2 * margin,
            (h - margin) * 2 - margin,
        )

        # Lynis-Style: 4 gedimmte Hintergrund-Sektoren ueber den
        # Halbkreis verteilt (Critical 0-39 / At Risk 40-64 / Moderate
        # 65-84 / Secure 85-100). Macht die 4 Stage-Zonen jederzeit
        # sichtbar, nicht nur den aktiven. Score-Bogen wird im naechsten
        # Schritt in voller Helligkeit dargestellt.
        self._paint_stage_backgrounds(painter, rect)

        # Wert-Bogen (nur wenn Score vorhanden) — voll-deckend, Farbe
        # der aktiven Stage. Liegt ueber den dimmed Background-Sektoren,
        # zeigt dadurch praezise wo der Score sitzt.
        if self._score is not None:
            color_hex = _resolve_stage_color(self._stage)
            pen_score = QPen(QColor(color_hex))
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

        # Stage-Label (klein, dezent unter der Zahl)
        painter.setPen(QColor(t.TEXT_DIM))
        font_status = QFont()
        font_status.setPointSize(9)
        painter.setFont(font_status)
        painter.drawText(
            QRectF(0, h * 0.72, w, h * 0.20),
            Qt.AlignmentFlag.AlignCenter,
            _stage_label(self._stage),
        )

    def _paint_stage_backgrounds(
        self,
        painter: QPainter,
        rect: QRectF,
    ) -> None:
        """Zeichnet 4 Hintergrund-Bogensektoren in Stage-Farben.

        Jeder Sektor deckt die Score-Range seiner Stage ab (z.B. Moderate
        65-84 → 19 von 100 Score-Punkten → 19/100 des 180-Grad-Bogens).
        Alpha ist reduziert (90/255 ≈ 35%), damit die Hintergrund-Sektoren
        zwar sichtbar bleiben, aber den aktiven Score-Bogen visuell nicht
        konkurrenzieren.
        """
        # SCORE_STAGES (Domain) iteriert ueber alle 4 Stufen mit
        # min_score/max_score. Wir mappen Score 0-100 auf 0-180 Grad
        # (Halbkreis-Bogen) — drawArc verlangt 1/16-Grad-Schritte.
        from tools.security_scoring.domain.hardening_stages import (  # noqa: PLC0415
            SCORE_STAGES,
        )

        stage_pen_alpha = 90  # 0..255 — Hintergrund subtle aber sichtbar
        for stage in SCORE_STAGES:
            color_hex = _resolve_stage_color(stage)
            color = QColor(color_hex)
            color.setAlpha(stage_pen_alpha)
            pen = QPen(color)
            pen.setWidth(_RING_WIDTH)
            pen.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen)
            # Stage-Range auf Bogen abbilden. Bogen geht im Uhrzeigersinn
            # (negativer span) ab 180-Grad (9-Uhr-Position).
            start_pct = stage.min_score / 100.0
            end_pct = (stage.max_score + 1) / 100.0  # +1 weil inkl.
            start_angle = int(
                (_HALF_CIRCLE_START_DEG - start_pct * _HALF_CIRCLE_SPAN_DEG)
                * _DEG
            )
            span_angle = -int(
                (end_pct - start_pct) * _HALF_CIRCLE_SPAN_DEG * _DEG
            )
            painter.drawArc(rect, start_angle, span_angle)

    # ------------------------------------------------------------------
    # Tooltip + Click
    # ------------------------------------------------------------------

    def _refresh_tooltip(self) -> None:
        """Baut den Tooltip-Text aus aktuellem Score + Stage neu."""
        if self._score is None or self._stage is None:
            self.setToolTip(
                "Noch kein Hardening-Score berechnet.\n"
                "Starte einen System-Scan, um den Score zu sehen."
            )
            return
        lines = [
            f"Hardening-Score: {self._score:.1f} — {self._stage.label}",
            "",
            "Stufen (ADR-008 v2):",
        ]
        for stage in SCORE_STAGES:
            marker = "►" if stage is self._stage else " "
            lines.append(
                f"  {marker} {stage.label}: {stage.min_score}-{stage.max_score}"
            )
        self.setToolTip("\n".join(lines))

    def mousePressEvent(self, event) -> None:  # noqa: ANN001, N802 — Qt-Override
        """Linksklick → ``clicked``-Signal."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_stage_color(stage: ScoreStage | None) -> str:
    """Resolved den Hex-Wert fuer eine Stage via:data:`SCORE_STAGE_COLORS`.

    Fallback: ``theme.get.BORDER`` (neutral grau) wenn keine Stage
    bekannt ist oder der ``color_key`` nicht im Theme-Dict steht.
    Letzteres deutet auf einen Drift zwischen Domain und Theme hin
    und wird waehrend Modul-Tests in:func:`validate_stages_cover_full_range`
    eigentlich abgefangen — Fallback ist defensive.
    """
    if stage is None:
        return theme.get().BORDER
    hex_value = theme.SCORE_STAGE_COLORS.get(stage.color_key)
    if hex_value is None:
        return theme.get().BORDER
    return hex_value


def _stage_label(stage: ScoreStage | None) -> str:
    """Status-Text fuer das untere Label im Gauge."""
    if stage is None:
        return "Keine Daten"
    return stage.label
