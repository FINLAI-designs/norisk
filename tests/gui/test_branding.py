"""GUI-Tests für ``core.branding`` — FINLAI-Roboter-Maskottchen.

Lockt den Vertrag von:func:`core.branding.robot_pixmap` ein:

* Asset lädt und liefert exakt ``size``×``size``.
* Kreismaske: Eckpixel sind transparent (Badge-Look).
* Modul-Dict-Cache: wiederholter Aufruf liefert dasselbe Objekt.

Headless via pytest-qt (``app``-Fixture aus tests/gui/conftest.py) —
QPixmap braucht eine laufende QApplication.
"""

from __future__ import annotations

import pytest

from core.branding import robot_pixmap

pytestmark = pytest.mark.gui


def test_robot_pixmap_nicht_null_und_64x64(app) -> None:  # noqa: ARG001
    """Das Roboter-Asset lädt und wird exakt auf 64×64 gebracht."""
    pm = robot_pixmap(64)
    assert not pm.isNull()
    assert pm.width() == 64
    assert pm.height() == 64


def test_robot_pixmap_eckpixel_transparent(app) -> None:  # noqa: ARG001
    """Kreismaske: beide obere Eckpixel liegen außerhalb des Kreises
    und müssen vollständig transparent sein."""
    img = robot_pixmap(64).toImage()
    assert img.pixelColor(0, 0).alpha() == 0
    assert img.pixelColor(63, 0).alpha() == 0


def test_robot_pixmap_cache_liefert_identisches_objekt(app) -> None:  # noqa: ARG001
    """Zweiter Aufruf mit gleicher Größe kommt aus dem Modul-Cache."""
    assert robot_pixmap(64) is robot_pixmap(64)


def test_robot_pixmap_fehlendes_asset_liefert_null(
    app, monkeypatch, tmp_path  # noqa: ARG001
) -> None:
    """Fallback-Vertrag: fehlendes Asset → Null-Pixmap, kein Crash.

    Genau dieser Pfad rettet den Login bei kaputtem Bundle — Aufrufer
    prüfen ``isNull`` und behalten ihr bisheriges Emblem/Icon.
    """
    from core import branding

    monkeypatch.setattr(branding, "_ROBOT_PATH", tmp_path / "fehlt.png")
    monkeypatch.setattr(branding, "_cache", {})
    assert branding.robot_pixmap(64).isNull()


def test_robot_pixmap_ungueltige_groesse_liefert_null(app) -> None:  # noqa: ARG001
    """size <= 0 wird abgewiesen statt QPainter-Warnungen zu erzeugen."""
    assert robot_pixmap(0).isNull()
    assert robot_pixmap(-5).isNull()
