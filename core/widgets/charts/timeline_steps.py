"""TimelineSteps — generischer Multi-Step-Timeline mit Live-Countdown.

Use-Cases im NoRisk-Sprint:
- NIS2 24h-/72h-/30d-Incident-Reporting-Phasen (Marketing-Hero)
- Wizard-Fortschritt mit Deadline (z.B. Risikoanalyse-Frist)
- Patch-Rollout-Stationen (Detect → Approve → Deploy → Verify)

Hexagonal-konform: nutzt nur ``PySide6``, ``core.theme`` und Python-Stdlib —
keine Domain-Imports.

Author: Patrick Riederich
Version: 0.1 (UI-Visualisierungs-Sprint)
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from core import theme

_PADDING = 16
_STEP_RADIUS = 18
_LINE_THICKNESS = 4
_LABEL_GAP = 12
_LABEL_WIDTH = 160
_LABEL_HEIGHT = 36
_LABEL_MIN_POINT = 9  # Untergrenze fuer auto-verkleinerte Label-Schrift
_COUNTDOWN_HEIGHT = 22
_COUNTDOWN_WARN_SECONDS = 6 * 3600
_COUNTDOWN_CRITICAL_SECONDS = 3600


class StepStatus(StrEnum):
    """Lebenszyklus einer Timeline-Station."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class TimelineStep:
    """Eine Station im Multi-Step-Timeline.

    Attributes:
        label: Anzeigename (z.B. ``"24h-Early-Warning"``).
        status: Aktueller Status der Station.
        deadline: Optionaler Fristzeitpunkt (UTC oder lokale Zeit, muss
            ``tzinfo``-fest sein). Wird fuer den Live-Countdown verwendet.
        detail: Hover-/Detail-Text. Wenn leer, wird ``label`` verwendet.
    """

    label: str
    status: StepStatus = StepStatus.PENDING
    deadline: datetime | None = None
    detail: str = ""


def format_remaining(total_seconds: float) -> str:
    """Formatiert eine Restzeit (in Sekunden) menschenlesbar.

    Args:
        total_seconds: Restzeit. Negative Werte werden als ``"abgelaufen"``
            ausgegeben.

    Returns:
        Strings wie ``"23h 12m"``, ``"04m 09s"``, ``"3T 04h"`` oder
        ``"abgelaufen"``.
    """
    if total_seconds < 0:
        return "abgelaufen"
    seconds = int(total_seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}T {hours:02d}h"
    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m"
    return f"{minutes:02d}m {secs:02d}s"


def countdown_color_for(remaining_seconds: float) -> str:
    """Liefert das Theme-Token (Hex-String) fuer einen Countdown-Wert.

    - ``< 1h`` → ``DARK_DANGER`` (rot)
    - ``< 6h`` → ``WARNING_ORANGE``
    - sonst → ``DARK_ACCENT``
    """
    if remaining_seconds < _COUNTDOWN_CRITICAL_SECONDS:
        return theme.DARK_DANGER
    if remaining_seconds < _COUNTDOWN_WARN_SECONDS:
        return theme.WARNING_ORANGE
    return theme.DARK_ACCENT


class TimelineSteps(QWidget):
    """Horizontaler Multi-Step-Timeline mit optionalem Live-Countdown.

    Signals:
        step_clicked(int): Index der angeklickten Station.

    Pflicht-API:
        -:meth:`set_steps` — Liste der Stationen.
        -:meth:`start_countdown_updates` /:meth:`stop_countdown_updates`
        - ``step_clicked: Signal(int)``.
    """

    step_clicked = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._steps: list[TimelineStep] = []
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._on_tick)
        self._now_fn = datetime.now  # Test-Hook fuer deterministischen Countdown

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.setMinimumSize(400, _STEP_RADIUS * 2 + _LABEL_HEIGHT + _COUNTDOWN_HEIGHT + 2 * _PADDING)
        self.setMouseTracking(True)

    def set_steps(self, steps: Sequence[TimelineStep]) -> None:
        """Aktualisiert die Stations-Liste und triggert Repaint."""
        self._steps = list(steps)
        self.updateGeometry()
        self.update()

    def start_countdown_updates(self) -> None:
        """Startet den 1-Sekunden-Tick fuer Live-Countdowns."""
        if not self._timer.isActive():
            self._timer.start()

    def stop_countdown_updates(self) -> None:
        """Stoppt den 1-Sekunden-Tick (z.B. wenn Widget unsichtbar)."""
        self._timer.stop()

    def _on_tick(self) -> None:
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        c = theme.get()
        painter.fillRect(self.rect(), QColor(c.BG_MAIN))

        if not self._steps:
            painter.setPen(QColor(c.TEXT_DIM))
            font = QFont()
            font.setPointSize(theme.FONT_SIZE_BODY)
            painter.setFont(font)
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "Keine Stationen",
            )
            painter.end()
            return

        centers = self._step_centers()
        line_y = centers[0].y()

        # Hintergrund-Linie zwischen erstem und letztem Step
        painter.setPen(QPen(QColor(c.BORDER), _LINE_THICKNESS, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(int(centers[0].x()), int(line_y), int(centers[-1].x()), int(line_y))

        # Aktive-/Done-Linie ueberzeichnen (bis zum letzten DONE/IN_PROGRESS)
        last_active_idx = -1
        for idx, step in enumerate(self._steps):
            if step.status in (StepStatus.DONE, StepStatus.IN_PROGRESS):
                last_active_idx = idx
        if last_active_idx >= 0:
            painter.setPen(QPen(QColor(theme.DARK_ACCENT), _LINE_THICKNESS, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawLine(
                int(centers[0].x()),
                int(line_y),
                int(centers[last_active_idx].x()),
                int(line_y),
            )

        # Stationen
        label_font = QFont()
        label_font.setPointSize(theme.FONT_SIZE_BODY_SM)
        label_font.setBold(True)
        countdown_font = QFont()
        countdown_font.setPointSize(theme.FONT_SIZE_CAPTION)

        for idx, (step, center) in enumerate(zip(self._steps, centers, strict=True)):
            fill, border, marker = self._colors_for(step.status)
            painter.setBrush(QColor(fill))
            painter.setPen(QPen(QColor(border), 2))
            painter.drawEllipse(center, _STEP_RADIUS, _STEP_RADIUS)

            # Marker-Glyphe (Tick / Number / Cross)
            painter.setPen(QColor(marker))
            painter.setFont(label_font)
            glyph = self._glyph_for(step.status, idx)
            painter.drawText(
                QRectF(
                    center.x() - _STEP_RADIUS,
                    center.y() - _STEP_RADIUS,
                    2 * _STEP_RADIUS,
                    2 * _STEP_RADIUS,
                ),
                Qt.AlignmentFlag.AlignCenter,
                glyph,
            )

            # Label unterhalb — Rand-Knoten werden an die Widget-Grenzen
            # geclampt, damit nichts abgeschnitten wird (T-livetest).
            painter.setPen(QColor(theme.DARK_TEXT_PRIMARY))
            label_rect = self._text_rect(
                center.x(),
                center.y() + _STEP_RADIUS + _LABEL_GAP,
                _LABEL_HEIGHT,
            )
            # Wortumbruch + auto-verkleinerte Schrift, damit lange
            # Rand-Labels lesbar bleiben statt abgeschnitten zu werden. Bei
            # Rand-Knoten ist label_rect fix auf ~98px geclampt; ein langer
            # unteilbarer Token wie "Incident" (aus "Post-Incident") passt dort
            # nicht in 12pt -> Schrift wird so weit verkleinert, dass der
            # breiteste Token passt (_fit_font). _LABEL_HEIGHT (36px) traegt zwei
            # Zeilen.
            painter.setFont(self._fit_font(step.label, label_rect.width(), label_font))
            painter.drawText(
                label_rect,
                int(Qt.AlignmentFlag.AlignTop)
                | int(Qt.AlignmentFlag.AlignHCenter)
                | int(Qt.TextFlag.TextWordWrap),
                step.label,
            )

            # Countdown unterhalb des Labels (nur fuer IN_PROGRESS mit deadline)
            if step.status == StepStatus.IN_PROGRESS and step.deadline is not None:
                remaining = self._remaining_seconds(step.deadline)
                painter.setPen(QColor(countdown_color_for(remaining)))
                painter.setFont(countdown_font)
                cd_rect = self._text_rect(
                    center.x(),
                    label_rect.bottom(),
                    _COUNTDOWN_HEIGHT,
                )
                painter.drawText(
                    cd_rect,
                    Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter,
                    format_remaining(remaining),
                )

        painter.end()

    @staticmethod
    def _fit_font(label: str, avail_width: float, base_font: QFont) -> QFont:
        """Verkleinert die Label-Schrift, bis der breiteste unteilbare Token passt.

        Qt bricht beim Zeichnen an Leerzeichen und Bindestrichen um; der
        breiteste Token nach diesem Split bestimmt die Mindestbreite einer
        Zeile. Passt er nicht in ``avail_width``, wird die Punktgroesse Schritt
        fuer Schritt bis ``_LABEL_MIN_POINT`` reduziert. So bleibt z.B.
        "Post-Incident" am rechten Rand (schmal geclamptes Rechteck) lesbar
        statt abgeschnitten.

        Args:
            label: Anzuzeigender Label-Text.
            avail_width: Verfuegbare Breite des Label-Rechtecks in px.
            base_font: Ausgangsschrift (wird nicht mutiert).

        Returns:
            Eine (ggf. verkleinerte) Kopie von ``base_font``.
        """
        tokens = [t for t in re.split(r"[\s\-]+", label) if t]
        if not tokens or avail_width <= 0:
            return base_font
        font = QFont(base_font)
        size = base_font.pointSize()
        while size > _LABEL_MIN_POINT:
            widest = max(QFontMetrics(font).horizontalAdvance(t) for t in tokens)
            if widest <= avail_width:
                break
            size -= 1
            font.setPointSize(size)
        return font

    def _colors_for(self, status: StepStatus) -> tuple[str, str, str]:
        """Liefert ``(fill, border, marker)`` fuer den Status."""
        if status == StepStatus.DONE:
            return theme.DARK_ACCENT, theme.DARK_ACCENT, theme.TEXT_ON_ACCENT_DEEP
        if status == StepStatus.IN_PROGRESS:
            return theme.DARK_BG_PRIMARY, theme.DARK_ACCENT, theme.DARK_ACCENT
        if status == StepStatus.SKIPPED:
            return theme.DARK_BG_BUTTON_DISABLED, theme.DARK_BORDER, theme.DARK_TEXT_DISABLED
        return theme.DARK_BG_INPUT, theme.DARK_BORDER, theme.DARK_TEXT_SECONDARY

    def _glyph_for(self, status: StepStatus, idx: int) -> str:
        if status == StepStatus.DONE:
            return "✓"  # check
        if status == StepStatus.SKIPPED:
            return "—"  # em dash
        return str(idx + 1)

    def _step_centers(self) -> list[QPointF]:
        if not self._steps:
            return []
        n = len(self._steps)
        y = _PADDING + _STEP_RADIUS
        if n == 1:
            return [QPointF(self.width() / 2.0, y)]
        # Die Knoten-MITTELPUNKTE muessen innerhalb von
        # ``[_PADDING + _STEP_RADIUS, width - _PADDING - _STEP_RADIUS]`` liegen,
        # damit der erste/letzte KREIS (Radius ``_STEP_RADIUS``) nicht ueber den
        # Rand hinausragt. Frueher wurde nur ``width - 2*_PADDING`` als Spanne
        # genommen, der letzte Center landete bei ``width - _PADDING +
        # _STEP_RADIUS`` -> der letzte Kreis war ~2*Radius (36px) ausserhalb und
        # damit unsichtbar (Patrick-Live-Test 2026-06-25, NIS2-Timeline D5).
        # Untergrenze ``2*_STEP_RADIUS*(n-1)`` haelt die Kreise auch auf sehr
        # schmaler Breite ueberschneidungsfrei.
        span = max(
            2 * _STEP_RADIUS * (n - 1),
            self.width() - 2 * _PADDING - 2 * _STEP_RADIUS,
        )
        step_dx = span / (n - 1)
        start_x = _PADDING + _STEP_RADIUS
        return [QPointF(start_x + idx * step_dx, y) for idx in range(n)]

    def _text_rect(self, center_x: float, top: float, height: float) -> QRectF:
        """Liefert das (geclampte) Text-Rechteck unterhalb eines Knotens.

        Das Label/Countdown ist nominell ``_LABEL_WIDTH`` breit und unter dem
        Knoten zentriert. Bei Rand-Knoten ragt es links unter 0 bzw. rechts
        ueber die Widget-Breite hinaus und wuerde abgeschnitten. Deshalb wird
        die linke Kante auf ``_PADDING`` und die rechte auf
        ``width - _PADDING`` geclampt; die Breite passt sich so an, ohne
        dass Text aus dem sichtbaren Bereich faellt.

        Args:
            center_x: X-Koordinate des Knoten-Mittelpunkts.
            top: Obere Kante des Text-Rechtecks.
            height: Hoehe des Text-Rechtecks.

        Returns:
            Ein an die Widget-Grenzen geclamptes ``QRectF``.
        """
        half = _LABEL_WIDTH / 2.0
        left = center_x - half
        right = center_x + half
        min_left = float(_PADDING)
        max_right = float(max(self.width() - _PADDING, _PADDING + 1))
        left = max(left, min_left)
        right = min(right, max_right)
        if right <= left:
            right = left + 1.0
        return QRectF(left, top, right - left, height)

    def _remaining_seconds(self, deadline: datetime) -> float:
        now = self._now_fn()
        if deadline.tzinfo is None and now.tzinfo is None:
            return (deadline - now).total_seconds()
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        return (deadline - now).total_seconds()

    def _step_at(self, pos: QPointF) -> int | None:
        centers = self._step_centers()
        for idx, center in enumerate(centers):
            if (pos - center).manhattanLength() <= _STEP_RADIUS * 1.5:
                # Exakter Kreis-Hittest
                dx = pos.x() - center.x()
                dy = pos.y() - center.y()
                if (dx * dx + dy * dy) <= _STEP_RADIUS * _STEP_RADIUS:
                    return idx
        return None

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        idx = self._step_at(event.position())
        if idx is not None:
            self.step_clicked.emit(idx)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001
        idx = self._step_at(event.position())
        if idx is None:
            QToolTip.hideText()
            return
        step = self._steps[idx]
        text = step.detail or step.label
        QToolTip.showText(event.globalPosition().toPoint(), text, self)

    def sizeHint(self) -> QSize:
        n = max(1, len(self._steps))
        w = max(400, n * 160)
        h = _STEP_RADIUS * 2 + _LABEL_HEIGHT + _COUNTDOWN_HEIGHT + 2 * _PADDING
        return QSize(w, h)


def _build_nis2_demo() -> TimelineSteps:
    """Demo-Helper: NIS2-6-Phasen mit aktivem 24h-Early-Warning + Deadline."""
    widget = TimelineSteps()
    from datetime import timedelta

    deadline = datetime.now() + timedelta(hours=18, minutes=42)
    steps = [
        TimelineStep("Detect", StepStatus.DONE),
        TimelineStep("Triage", StepStatus.DONE),
        TimelineStep(
            "24h Early-Warning",
            StepStatus.IN_PROGRESS,
            deadline=deadline,
            detail="Frist Art. 23 NIS2 (24h ab Awareness)",
        ),
        TimelineStep("72h Notification", StepStatus.PENDING),
        TimelineStep("30d Final-Report", StepStatus.PENDING),
        TimelineStep("Post-Incident", StepStatus.PENDING),
    ]
    widget.set_steps(steps)
    widget.resize(900, 130)
    return widget


if __name__ == "__main__":  # pragma: no cover - Demo-Snippet
    import sys

    from PySide6.QtWidgets import QApplication

    qapp = QApplication(sys.argv)
    theme.apply(qapp)
    demo = _build_nis2_demo()
    demo.setWindowTitle("TimelineSteps Demo — NIS2 Art. 23")
    demo.start_countdown_updates()
    demo.show()
    sys.exit(qapp.exec())
