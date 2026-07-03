"""test_startup_window_window_flags — Fenster-Verhalten von Startup & Overlay.

Sichert den Fix aus ab: Der Start-/Login-/Erststart-Screen darf den
Bildschirm nicht mehr komplett abdecken. Konkret:
- ``StartupWindow`` hat KEIN ``WindowStaysOnTopHint`` und ist ein echtes
  Top-Level-Fenster (``Qt.Window``, Taskbar/Alt+Tab) mit ``FramelessWindowHint``.
- ``show_centered`` zeigt das Fenster nicht maximiert in fester Größe.
- Das Fenster lässt sich per Maus verschieben (Frameless hat keinen System-Drag).
- ``AppLoadingOverlay`` setzt im Standalone-Modus kein ``WindowStaysOnTopHint``.
"""

from __future__ import annotations

import pytest
from apps.app_config import NORISK_CONFIG
from PySide6.QtCore import QEvent, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QWidget

from core.loading_overlay import AppLoadingOverlay
from core.startup_window import StartupWindow

pytestmark = pytest.mark.gui


class TestStartupWindowFlags:
    """Testet Window-Flags und zentrierte Anzeige des StartupWindow."""

    @pytest.fixture
    def startup(self, qtbot, app):
        """Erstellt ein StartupWindow für Tests."""
        window = StartupWindow(NORISK_CONFIG)
        qtbot.addWidget(window)
        return window

    def test_kein_stays_on_top(self, startup):
        """StartupWindow blockiert nicht den Vordergrund (kein StaysOnTop)."""
        flags = startup.windowFlags()
        assert not (flags & Qt.WindowType.WindowStaysOnTopHint)

    def test_ist_top_level_fenster(self, startup):
        """Qt.Window + Frameless: Taskbar-Eintrag bei erhaltenem Splash-Look."""
        flags = startup.windowFlags()
        assert flags & Qt.WindowType.Window
        assert flags & Qt.WindowType.FramelessWindowHint

    def test_show_centered_nicht_maximiert(self, startup):
        """show_centered zeigt das Fenster nicht maximiert und nicht mehr im
        grossen 760x620-Startformat: kompakt wie das Login-Fenster)."""
        startup.show_centered()
        assert not startup.isMaximized()
        assert not startup.isFullScreen()
        # Nicht mehr das fuer eingebettete Startup-Dialoge dimensionierte Fenster.
        assert startup.width() < 760

    def test_vor_login_und_login_gleiche_groesse(self, startup):
        """: Das Fenster VOR der Anmeldung hat dieselbe Größe wie das
        Login-Fenster — kein sichtbarer Größensprung (Patrick-Live-Test 2026-06-27).

        Regression davor: ``show_centered`` zeigte das für die eingebetteten
        Startup-Dialoge dimensionierte 760x620-Fenster und ``show_login``
        schrumpfte es dann auf die schmale Login-Karte — ein sichtbarer Sprung.
        Jetzt nutzen beide dieselbe kompakte Login-Größe.
        """
        startup.show_centered()
        vor = startup.width()
        startup.show_login()
        assert startup.width() == vor  # kein Größensprung
        assert startup.width() < 600  # kompakt (deutlich schmaler als 760)

    def test_drag_verschiebt_fenster(self, startup):
        """Ziehen mit linker Maustaste verschiebt das Fenster um das Delta."""
        startup.show_centered()
        start = startup.pos()

        startup._drag_pos = QPointF(100.0, 100.0).toPoint()
        move = QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(0.0, 0.0),
            QPointF(140.0, 130.0),  # globale Cursor-Position: Delta (+40, +30)
            Qt.MouseButton.NoButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        startup.mouseMoveEvent(move)

        assert startup.pos().x() == start.x() + 40
        assert startup.pos().y() == start.y() + 30


class TestLoadingOverlayFlags:
    """Testet die Window-Flags des Re-Login-Ladescreens."""

    def test_standalone_kein_stays_on_top(self, qtbot, app):
        """Standalone-Overlay (parent=None) blockiert nicht den Vordergrund."""
        overlay = AppLoadingOverlay(NORISK_CONFIG)
        qtbot.addWidget(overlay)
        flags = overlay.windowFlags()
        assert not (flags & Qt.WindowType.WindowStaysOnTopHint)
        assert flags & Qt.WindowType.Window

    def test_child_kein_eigenes_fenster(self, qtbot, app):
        """Kind-Overlay (parent=MainWindow) ist kein eigenes Top-Level-Fenster."""
        host = QWidget()
        qtbot.addWidget(host)
        overlay = AppLoadingOverlay(NORISK_CONFIG, parent=host)
        assert overlay.isWindow() is False
