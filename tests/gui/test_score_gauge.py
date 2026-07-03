"""Tests für ``ScoreGauge`` + ``ScoreSection`` (Sprint S3b).

Deckt ab:
  - Farbzonen-Mapping (cve_exposure-Schwellen 60/80) per
    ``_color_for_score``.
  - Status-Label-Mapping (``_status_label``).
  - Tooltip enthält Komponenten-Aufschlüsselung.
  - Linksklick → ``clicked``-Signal.
  - ``ScoreSection.update_data(snapshot, breakdown)`` reicht den
    ``score``-Wert an den Gauge weiter.
  - ``ScoreSection.clicked`` wird sowohl von Tile als auch Gauge
    emittiert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent

from core import theme
from tools.norisk_dashboard.domain.models import ScoreSnapshot
from tools.norisk_dashboard.gui.score_gauge import (
    ScoreGauge,
    _color_for_score,
    _status_label,
)
from tools.norisk_dashboard.gui.section_score import ScoreSection
from tools.security_scoring.domain.models import ScoreComponent

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# _color_for_score
# ---------------------------------------------------------------------------


def test_color_zone_ok_green(app):  # noqa: ARG001 -- app aktiviert QApplication
    """Score >= 80 → SUCCESS (grün)."""
    t = theme.get()
    assert _color_for_score(80.0, t) == t.SUCCESS
    assert _color_for_score(95.0, t) == t.SUCCESS


def test_color_zone_warn_orange(app):  # noqa: ARG001
    """60 <= Score < 80 → WARNING_ORANGE."""
    t = theme.get()
    assert _color_for_score(60.0, t) == theme.WARNING_ORANGE
    assert _color_for_score(79.9, t) == theme.WARNING_ORANGE


def test_color_zone_kritisch_red(app):  # noqa: ARG001
    """Score < 60 → DANGER (rot)."""
    t = theme.get()
    assert _color_for_score(59.9, t) == t.DANGER
    assert _color_for_score(0.0, t) == t.DANGER


# ---------------------------------------------------------------------------
# _status_label
# ---------------------------------------------------------------------------


def test_status_label_zonen():
    """Status-Label folgt denselben Schwellen wie ``cve_exposure``."""
    assert _status_label(85.0) == "OK"
    assert _status_label(80.0) == "OK"
    assert _status_label(79.9) == "Warnung"
    assert _status_label(60.0) == "Warnung"
    assert _status_label(59.9) == "Kritisch"
    assert _status_label(None) == "Keine Daten"


# ---------------------------------------------------------------------------
# ScoreGauge — Tooltip
# ---------------------------------------------------------------------------


def test_gauge_tooltip_ohne_score(qtbot):
    """Ohne Score: Tooltip enthält den 'noch kein Score'-Hinweis."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)
    assert "Starte einen Scan" in gauge.toolTip()


def test_gauge_tooltip_mit_score_und_komponenten(qtbot):
    """Tooltip listet alle Komponenten auf."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)
    breakdown = [
        ScoreComponent(
            name="API Security", score=92, weight=0.25, data_available=True
        ),
        ScoreComponent(
            name="Netzwerk", score=70, weight=0.20, data_available=True
        ),
        ScoreComponent(
            name="CVE-Exposition",
            score=0,
            weight=0.15,
            data_available=False,
        ),
    ]
    gauge.set_data(85.0, breakdown)
    tooltip = gauge.toolTip()
    assert "85.0" in tooltip
    assert "OK" in tooltip
    assert "API Security" in tooltip
    assert "Netzwerk" in tooltip
    assert "CVE-Exposition" in tooltip


def test_gauge_tooltip_ohne_komponenten_zeigt_hinweis(qtbot):
    """Score gesetzt aber keine Komponenten → 'noch keine Komponenten-Daten'."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)
    gauge.set_data(72.0, breakdown=None)
    assert "Komponenten-Daten verfügbar" in gauge.toolTip()


# ---------------------------------------------------------------------------
# ScoreGauge — Click-Signal
# ---------------------------------------------------------------------------


def test_gauge_linksklick_emittiert_clicked(qtbot):
    """Linksklick → ``clicked``-Signal."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)

    received: list[None] = []
    gauge.clicked.connect(lambda: received.append(None))

    event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPoint(50, 50),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    gauge.mousePressEvent(event)
    assert len(received) == 1


def test_gauge_rechtsklick_emittiert_nicht(qtbot):
    """Rechtsklick → kein Signal (nur Linksklick zählt)."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)

    received: list[None] = []
    gauge.clicked.connect(lambda: received.append(None))

    event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPoint(50, 50),
        Qt.MouseButton.RightButton,
        Qt.MouseButton.RightButton,
        Qt.KeyboardModifier.NoModifier,
    )
    gauge.mousePressEvent(event)
    assert received == []


# ---------------------------------------------------------------------------
# ScoreGauge — set_data
# ---------------------------------------------------------------------------


def test_gauge_set_data_score_none_zeigt_dash(qtbot):
    """``set_data(None)`` setzt den Tooltip auf den Empty-State."""
    gauge = ScoreGauge()
    qtbot.add_widget(gauge)
    gauge.set_data(72.0, [])
    gauge.set_data(None, None)
    assert "Starte einen Scan" in gauge.toolTip()


# ---------------------------------------------------------------------------
# ScoreSection — Wiring
# ---------------------------------------------------------------------------


def test_section_update_data_reicht_score_an_gauge(qtbot):
    """``ScoreSection.update_data(snapshot, breakdown)`` füllt den Gauge."""
    section = ScoreSection()
    qtbot.add_widget(section)
    snap = ScoreSnapshot(current=88.0, previous=85.0)
    breakdown = [
        ScoreComponent(name="X", score=88.0, weight=1.0, data_available=True),
    ]
    section.update_data(snap, breakdown)
    assert section._gauge._score == 88.0  # noqa: SLF001
    assert "OK" in section._gauge.toolTip()  # noqa: SLF001


def test_section_update_data_ohne_breakdown_funktioniert(qtbot):
    """Backwards-Compat: ``update_data(snap)`` ohne breakdown bleibt erlaubt."""
    section = ScoreSection()
    qtbot.add_widget(section)
    snap = ScoreSnapshot(current=42.0)
    section.update_data(snap)  # Default: breakdown=None
    assert section._gauge._score == 42.0  # noqa: SLF001


def test_section_clicked_kommt_aus_gauge(qtbot):
    """Gauge-Klick emittiert auf ``ScoreSection.clicked``."""
    section = ScoreSection()
    qtbot.add_widget(section)

    received: list[None] = []
    section.clicked.connect(lambda: received.append(None))

    event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPoint(10, 10),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    section._gauge.mousePressEvent(event)  # noqa: SLF001
    assert len(received) == 1
