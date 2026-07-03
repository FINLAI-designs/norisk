"""Tests fuer den Kernel-Process-Pfad-Tracker Regel 4)."""

from __future__ import annotations

from tools.network_monitor.data.process_path_tracker import (
    KERNEL_PROCESS_START_EVENT_ID,
    ProcessPathTracker,
)


class TestProcessPathTracker:
    def test_processstart_speichert_pfad(self) -> None:
        t = ProcessPathTracker()
        t.add_event(
            KERNEL_PROCESS_START_EVENT_ID,
            {"ProcessID": 1234, "ImageName": r"C:\Temp\x.exe"},
        )
        assert t.resolve(1234) == r"C:\Temp\x.exe"

    def test_anderes_event_ignoriert(self) -> None:
        t = ProcessPathTracker()
        t.add_event(10, {"ProcessID": 1, "ImageName": "x"})
        assert t.resolve(1) == ""

    def test_unbekannte_pid_leer(self) -> None:
        assert ProcessPathTracker().resolve(99) == ""

    def test_fehlende_felder_ignoriert(self) -> None:
        t = ProcessPathTracker()
        t.add_event(KERNEL_PROCESS_START_EVENT_ID, {"ProcessID": 5})  # kein image
        t.add_event(KERNEL_PROCESS_START_EVENT_ID, {"ImageName": "y"})  # keine pid
        assert t.resolve(5) == ""

    def test_string_pid_coercion(self) -> None:
        t = ProcessPathTracker()
        t.add_event(
            KERNEL_PROCESS_START_EVENT_ID,
            {"ProcessID": "77", "ImageName": "z.exe"},
        )
        assert t.resolve(77) == "z.exe"
