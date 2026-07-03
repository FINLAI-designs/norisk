"""test_startup_window_embedded — Tests für StartupWindow.run_embedded.

Sichert den Port aus ab: Startup-Dialoge (Lizenz, AGB, Datenschutz,
GDPR, First-Run) werden als eingebettete Seiten im StartupWindow-Stack
gezeigt statt als Popups, die hinter dem Startfenster verschwinden oder den
ganzen Bildschirm überlagern können.

Statt einer echten Anzeige wird der QDialog headless via QTimer accept/reject
geschlossen; ``run_embedded`` blockiert solange in einem lokalen QEventLoop.
"""

from __future__ import annotations

import pytest
from apps.app_config import NORISK_CONFIG
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QDialog

from core.startup_window import StartupWindow

pytestmark = pytest.mark.gui


class TestRunEmbedded:
    """Testet den eingebetteten Dialog-Schritt des StartupWindow."""

    @pytest.fixture
    def startup(self, qtbot, app):
        """Erstellt ein StartupWindow für Tests (nicht maximiert gezeigt)."""
        window = StartupWindow(NORISK_CONFIG)
        qtbot.addWidget(window)
        return window

    def test_accept_returns_accepted(self, startup):
        """Dialog.accept → run_embedded liefert Accepted."""
        dialog = QDialog()
        QTimer.singleShot(0, dialog.accept)
        result = startup.run_embedded(dialog)
        assert result == QDialog.DialogCode.Accepted

    def test_reject_returns_rejected(self, startup):
        """Dialog.reject → run_embedded liefert Rejected."""
        dialog = QDialog()
        QTimer.singleShot(0, dialog.reject)
        result = startup.run_embedded(dialog)
        assert result == QDialog.DialogCode.Rejected

    def test_stack_restored_after_run(self, startup):
        """Nach dem Schritt ist die Host-Seite entfernt und die vorherige
        Seite (Ladescreen) wieder aktiv — Indizes bleiben stabil."""
        count_before = startup._stack.count()
        index_before = startup._stack.currentIndex()

        dialog = QDialog()
        QTimer.singleShot(0, dialog.accept)
        startup.run_embedded(dialog)

        assert startup._stack.count() == count_before
        assert startup._stack.currentIndex() == index_before

    def test_dialog_detached_and_readable_after_run(self, startup):
        """Der Dialog wird vom Host gelöst und bleibt nach Rückkehr lesbar
        (Aufrufer liest z. B. was_accepted / result_info)."""
        dialog = QDialog()
        marker = {"done": False}
        dialog.accepted.connect(lambda: marker.__setitem__("done", True))
        QTimer.singleShot(0, dialog.accept)
        startup.run_embedded(dialog)

        assert dialog.parent() is None
        assert dialog.isVisible() is False
        assert marker["done"] is True

    def test_dialog_rendered_as_child_during_run(self, startup):
        """Während des Schritts ist der Dialog ein eingebettetes Kind-Widget
        (kein eigenes Top-Level-Fenster) und die Host-Seite ist aktiv."""
        dialog = QDialog()
        observed: dict[str, object] = {}

        def _inspect() -> None:
            observed["is_window"] = dialog.isWindow()
            observed["current_is_host"] = (
                startup._stack.currentWidget() is not None
                and startup._stack.currentWidget() is dialog.parentWidget()
            )
            dialog.accept()

        QTimer.singleShot(0, _inspect)
        startup.run_embedded(dialog)

        assert observed["is_window"] is False
        assert observed["current_is_host"] is True
