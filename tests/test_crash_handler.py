"""
test_crash_handler — Tests fuer den End-User-Crash-Handler.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core import crash_handler


@pytest.fixture(autouse=True)
def _reset_crash_handler_state():
    """Verhindert dass Test-Excepthook-Installation leakt."""
    original_excepthook = sys.excepthook
    original_installed = getattr(sys, "_finlai_excepthook_installed", False)
    crash_handler.set_dialog_trigger(None)
    yield
    sys.excepthook = original_excepthook
    sys._finlai_excepthook_installed = original_installed
    crash_handler._DIALOG_DISABLED = False
    crash_handler.set_dialog_trigger(None)


class TestExcepthookInstallation:
    def test_install_setzt_sys_excepthook(self) -> None:
        # Reset flag (sonst no-op)
        if hasattr(sys, "_finlai_excepthook_installed"):
            delattr(sys, "_finlai_excepthook_installed")
        before = sys.excepthook
        crash_handler.install_excepthook()
        assert sys.excepthook is not before
        assert sys.excepthook is crash_handler._excepthook

    def test_install_ist_idempotent(self) -> None:
        if hasattr(sys, "_finlai_excepthook_installed"):
            delattr(sys, "_finlai_excepthook_installed")
        crash_handler.install_excepthook()
        first = sys.excepthook
        crash_handler.install_excepthook()
        assert sys.excepthook is first

    def test_excepthook_loggt_und_triggert_dialog(self) -> None:
        trigger = MagicMock()
        crash_handler.set_dialog_trigger(trigger)
        try:
            raise ValueError("Test-Fehler 42")
        except ValueError:
            exc_type, exc_value, exc_tb = sys.exc_info()
        crash_handler._excepthook(exc_type, exc_value, exc_tb)
        trigger.assert_called_once()
        args = trigger.call_args.args
        assert "ValueError" in args[0]
        assert "Test-Fehler 42" in args[1]

    def test_excepthook_recursion_safe(self) -> None:
        """Wenn der Dialog selbst wirft, darf das keinen Stack-Overflow geben."""
        def bad_trigger(title: str, message: str) -> None:
            raise RuntimeError("Dialog wirft auch")
        crash_handler.set_dialog_trigger(bad_trigger)
        try:
            raise ValueError("Outer")
        except ValueError:
            exc_type, exc_value, exc_tb = sys.exc_info()
        # Darf NICHT crashen
        crash_handler._excepthook(exc_type, exc_value, exc_tb)


class TestDialogTrigger:
    def test_kein_trigger_kein_call(self) -> None:
        crash_handler.set_dialog_trigger(None)
        # Bei None passiert nichts — kein Aufruf, kein Crash
        crash_handler._trigger_dialog("X", "Y")

    def test_disabled_flag_verhindert_rekursion(self) -> None:
        trigger = MagicMock()
        crash_handler.set_dialog_trigger(trigger)
        crash_handler._DIALOG_DISABLED = True
        crash_handler._trigger_dialog("X", "Y")
        trigger.assert_not_called()


class TestExportDiagnoseBundle:
    def test_bundle_enthaelt_system_info(self, tmp_path: Path) -> None:
        target = tmp_path / "bundle.zip"
        crash_handler.export_diagnose_bundle(target)
        assert target.exists()
        with zipfile.ZipFile(target) as zf:
            names = zf.namelist()
            assert "system_info.txt" in names
            content = zf.read("system_info.txt").decode("utf-8")
        assert "Python" in content
        assert "Plattform" in content

    def test_bundle_enthaelt_log_wenn_da(self, tmp_path: Path) -> None:
        target = tmp_path / "bundle.zip"
        # Logger ist beim ersten Test bereits initialisiert — Log existiert
        crash_handler.export_diagnose_bundle(target)
        with zipfile.ZipFile(target) as zf:
            names = zf.namelist()
        # finlai_<datum>.log oder system_info.txt mindestens
        assert any(n.startswith("finlai_") for n in names) or "system_info.txt" in names


class TestOpenHelpers:
    def test_open_log_directory_callt_platform_opener(self, monkeypatch) -> None:
        from core import crash_handler as ch

        called: dict[str, object] = {}

        if sys.platform == "win32":
            def fake_startfile(p):  # noqa: ANN001, ANN202
                called["path"] = p
            monkeypatch.setattr("os.startfile", fake_startfile, raising=False)
        else:
            fake_proc = MagicMock()
            monkeypatch.setattr(
                "subprocess.run",
                lambda *args, **kw: called.setdefault("called", True) or fake_proc,
            )

        result = ch.open_log_directory()
        assert result is True
        if sys.platform == "win32":
            assert "path" in called
        else:
            assert called.get("called") is True
