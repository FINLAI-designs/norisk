"""tests/test_dock_floating_restore.py — Regressionstests gegen den
„toter Sidebar-Eintrag"-Bug (freischwebendes Dock off-screen).

Spiegelung eines Schwester-App-Fixes (dock-restore-offscreen) in NoRisks
Mixin-Struktur:

* ``DockMixin._redock_floating`` — dockt freischwebend persistierte Tool-Docks
  beim Restore zwangsweise wieder an (struktureller Hauptfix; Floating ist nur
  transienter Laufzeit-Zustand).
* ``NavigationMixin._ensure_dock_on_screen`` — holt ein off-screen
  freischwebendes Dock zur Laufzeit zurück (Sicherheitsnetz).
"""

from __future__ import annotations

import sys

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDockWidget, QMainWindow

from core.dock_mixin import DockMixin
from core.navigation_mixin import NavigationMixin


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication(sys.argv)
    yield instance


class TestRedockFloating:
    """``DockMixin._redock_floating`` — Floating-Docks wieder andocken."""

    def test_floating_dock_wird_angedockt(self, app):
        host = QMainWindow()
        dock = QDockWidget("Test", host)
        host.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        dock.setFloating(True)
        assert dock.isFloating()

        DockMixin._redock_floating([dock])

        assert not dock.isFloating()

    def test_angedocktes_dock_bleibt_unveraendert(self, app):
        host = QMainWindow()
        dock = QDockWidget("Test", host)
        host.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        assert not dock.isFloating()

        DockMixin._redock_floating([dock])

        assert not dock.isFloating()


class TestEnsureDockOnScreen:
    """``NavigationMixin._ensure_dock_on_screen`` — off-screen zurückholen."""

    def _on_any_screen(self, dock: QDockWidget) -> bool:
        frame = dock.frameGeometry()
        return any(
            scr.availableGeometry().intersects(frame)
            for scr in QApplication.screens()
        )

    def test_offscreen_floating_dock_wird_zurueckgeholt(self, app):
        host = QMainWindow()
        dock = QDockWidget("Test", host)
        host.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        dock.setFloating(True)
        dock.move(-20000, -20000)

        NavigationMixin._ensure_dock_on_screen(dock)

        assert self._on_any_screen(dock)

    def test_nicht_floating_dock_unveraendert(self, app):
        host = QMainWindow()
        dock = QDockWidget("Test", host)
        host.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        pos_before = dock.pos()

        NavigationMixin._ensure_dock_on_screen(dock)

        assert dock.pos() == pos_before
