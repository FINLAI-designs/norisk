"""test_dock_title_bar_drag/ DockTitleBar Drag-Logik."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QDockWidget, QMainWindow

from core.widgets.dock_title_bar import DockTitleBar


def _make_dock_with_title_bar(parent=None) -> tuple[QMainWindow, QDockWidget, DockTitleBar]:
    """Hilfsfunktion: MainWindow + andocktes QDockWidget mit DockTitleBar."""
    main = QMainWindow(parent)
    main.resize(800, 600)
    dock = QDockWidget("Test-Dock", main)
    bar = DockTitleBar("Test-Dock", dock)
    dock.setTitleBarWidget(bar)
    main.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
    main.show()
    return main, dock, bar


def _mouse_event(
    event_type: QEvent.Type,
    pos: QPoint,
    global_pos: QPoint,
    button: Qt.MouseButton = Qt.MouseButton.LeftButton,
    buttons: Qt.MouseButton | None = None,
) -> QMouseEvent:
    """Hilfsfunktion: erzeugt ein QMouseEvent mit allen 5 Pflicht-Args fuer PySide6."""
    if buttons is None:
        buttons = button
    return QMouseEvent(
        event_type,
        QPointF(pos),
        QPointF(global_pos),
        button,
        buttons,
        Qt.KeyboardModifier.NoModifier,
    )


class TestDragInitialState:
    """Default-State: kein aktiver Drag."""

    def test_no_drag_state_at_init(self, app) -> None:
        main, _dock, bar = _make_dock_with_title_bar()
        try:
            assert bar._drag_start_pos is None
            assert bar._drag_global_offset is None
        finally:
            main.close()


class TestDragStart:
    """``mousePressEvent`` mit Linksklick speichert Drag-Start."""

    def test_left_click_setzt_drag_state(self, app) -> None:
        main, _dock, bar = _make_dock_with_title_bar()
        try:
            ev = _mouse_event(
                QEvent.Type.MouseButtonPress,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mousePressEvent(ev)
            assert bar._drag_start_pos == QPoint(50, 18)
            assert bar._drag_global_offset is not None
        finally:
            main.close()

    def test_rechtsklick_kein_drag_state(self, app) -> None:
        main, _dock, bar = _make_dock_with_title_bar()
        try:
            ev = _mouse_event(
                QEvent.Type.MouseButtonPress,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
                button=Qt.MouseButton.RightButton,
            )
            bar.mousePressEvent(ev)
            assert bar._drag_start_pos is None
        finally:
            main.close()


class TestDragRelease:
    """``mouseReleaseEvent`` setzt Drag-State zurueck."""

    def test_release_resets_state(self, app) -> None:
        main, _dock, bar = _make_dock_with_title_bar()
        try:
            # Press + Release
            press = _mouse_event(
                QEvent.Type.MouseButtonPress,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mousePressEvent(press)
            assert bar._drag_start_pos is not None

            release = _mouse_event(
                QEvent.Type.MouseButtonRelease,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mouseReleaseEvent(release)
            assert bar._drag_start_pos is None
            assert bar._drag_global_offset is None
        finally:
            main.close()


class TestDoubleClickToggleFloat:
    """Doppelklick auf Title-Bar = Float-Toggle."""

    def test_doppelklick_floated(self, app) -> None:
        main, dock, bar = _make_dock_with_title_bar()
        try:
            assert dock.isFloating() is False
            ev = _mouse_event(
                QEvent.Type.MouseButtonDblClick,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mouseDoubleClickEvent(ev)
            assert dock.isFloating() is True
        finally:
            main.close()


class TestDragMoveTriggertFloat:
    """Maus-Move ueber Drag-Threshold setzt Dock auf floating."""

    def test_kleine_bewegung_kein_float(self, app) -> None:
        main, dock, bar = _make_dock_with_title_bar()
        try:
            press = _mouse_event(
                QEvent.Type.MouseButtonPress,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mousePressEvent(press)

            # Mikro-Bewegung von 1 px sollte NICHT zu Floating fuehren
            move = _mouse_event(
                QEvent.Type.MouseMove,
                QPoint(51, 18),
                bar.mapToGlobal(QPoint(51, 18)),
                button=Qt.MouseButton.NoButton,
                buttons=Qt.MouseButton.LeftButton,
            )
            bar.mouseMoveEvent(move)
            assert dock.isFloating() is False
        finally:
            main.close()

    def test_grosse_bewegung_triggert_float(self, app) -> None:
        main, dock, bar = _make_dock_with_title_bar()
        try:
            press = _mouse_event(
                QEvent.Type.MouseButtonPress,
                QPoint(50, 18),
                bar.mapToGlobal(QPoint(50, 18)),
            )
            bar.mousePressEvent(press)

            # Grosse Bewegung (300 px) ueber Drag-Threshold -> floating
            move = _mouse_event(
                QEvent.Type.MouseMove,
                QPoint(350, 18),
                bar.mapToGlobal(QPoint(350, 18)),
                button=Qt.MouseButton.NoButton,
                buttons=Qt.MouseButton.LeftButton,
            )
            bar.mouseMoveEvent(move)
            assert dock.isFloating() is True
        finally:
            main.close()
