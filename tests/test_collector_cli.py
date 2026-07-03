"""Tests fuer das Collector-CLI-Dispatch in apps.norisk_app Phase C).

Mockt die lazy importierten Task-/Collector-Funktionen — kein echter
Task-Scheduler-Zugriff, kein echter ETW-Lauf.
"""

from __future__ import annotations

import sys

import pytest
from apps.norisk_app import _run_collector_cli

_CTM = "tools.network_monitor.data.collector_task_manager"


@pytest.fixture(autouse=True)
def _isolate_marker_and_home(monkeypatch):
    """Marker-IO mocken UND den globalen FINLAI_HOME-Override nach jedem Test zurücksetzen.

    Der Install-Zweig ruft seit F-C-5 ``set_finlai_home(finlai_home)``, wenn
    ``--finlai-home`` gesetzt ist (damit der Reject-Marker im richtigen Profil
    landet). Im geteilten pytest-Prozess würde dieser Override sonst in Folgetests
    lecken und ``finlai_dir``-abhängige Tests (z. B. CSAF-Techstack, der
    ``Path.home`` patcht, aber vom Override übersteuert wird) brechen.
    """
    from core import finlai_paths  # noqa: PLC0415

    monkeypatch.setattr(f"{_CTM}.write_install_reject_marker", lambda reason: None)
    monkeypatch.setattr(f"{_CTM}.clear_install_marker", lambda: None)
    saved = finlai_paths.finlai_home_override()
    yield
    finlai_paths.set_finlai_home(saved)


def test_kein_flag_gibt_none() -> None:
    assert _run_collector_cli(["norisk_app.py"]) is None


def test_install_flag_dev_ruft_install(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        lambda **kw: calls.update(kw, called=True),
    )
    rc = _run_collector_cli(["norisk_app.py", "--install-collector-task"])
    assert rc == 0
    assert calls.get("called") is True
    # Dev-Pfad: kein exe/arguments-Override
    assert "exe" not in calls


def test_install_flag_frozen_delegiert_an_default_action(monkeypatch) -> None:
    # F-C: gepackt UND dev installieren ueber default_collector_action
    # (frozen-aware -> separate norisk-collector.exe). Der Entry uebergibt KEINEN
    # exe/arguments-Override mehr, damit Installer und
    # collector_task_needs_migration dieselbe Single-Source nutzen (kein
    # Exe-Pfad-Drift -> kein Dauer-„Migration noetig"/UAC-Schleife).
    calls = {}
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\app\norisk.exe")
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        lambda **kw: calls.update(kw, called=True),
    )
    rc = _run_collector_cli(["norisk.exe", "--install-collector-task"])
    assert rc == 0
    assert calls.get("called") is True
    assert "exe" not in calls
    assert "arguments" not in calls


def test_install_fehler_gibt_1(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    def boom(**kw):
        raise PermissionError("kein Admin")

    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        boom,
    )
    rc = _run_collector_cli(["norisk_app.py", "--install-collector-task"])
    assert rc == 1


def test_install_untrusted_pfad_gibt_3_und_schreibt_marker(monkeypatch) -> None:
    # Security-Gate lehnt fail-closed ab -> eigener Exit-Code 3 (nicht 1) UND
    # Marker-Datei, damit der GUI-Pfad (F-C-5) den Reject erklären kann.
    from tools.network_monitor.domain.exceptions import UntrustedCollectorPathError

    monkeypatch.setattr(sys, "frozen", False, raising=False)

    def boom(**kw):
        raise UntrustedCollectorPathError("benutzer-beschreibbar")

    monkeypatch.setattr(f"{_CTM}.install_collector_task", boom)
    written = {}
    monkeypatch.setattr(
        f"{_CTM}.write_install_reject_marker",
        lambda reason: written.update(reason=reason),
    )
    rc = _run_collector_cli(["norisk_app.py", "--install-collector-task"])
    assert rc == 3
    assert "reason" in written


def test_install_erfolg_clears_marker(monkeypatch) -> None:
    # Erfolg entfernt einen evtl. alten Reject-Marker einer früheren Aktivierung.
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(f"{_CTM}.install_collector_task", lambda **kw: None)
    cleared = {"v": False}
    monkeypatch.setattr(
        f"{_CTM}.clear_install_marker", lambda: cleared.__setitem__("v", True)
    )
    rc = _run_collector_cli(["norisk_app.py", "--install-collector-task"])
    assert rc == 0
    assert cleared["v"] is True


def test_uninstall_flag_ruft_uninstall(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.uninstall_collector_task",
        lambda: calls.update(called=True) or True,
    )
    rc = _run_collector_cli(["norisk_app.py", "--uninstall-collector-task"])
    assert rc == 0
    assert calls.get("called") is True


def test_run_collector_flag_ruft_collector_main(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(
        "apps.collector_main.main",
        lambda argv: calls.update(argv=argv) or 0,
    )
    rc = _run_collector_cli(["norisk_app.py", "--run-collector"])
    assert rc == 0
    assert calls["argv"] == []


def test_install_reicht_finlai_home_durch(monkeypatch) -> None:
    calls = {}
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        lambda **kw: calls.update(kw),
    )
    rc = _run_collector_cli(
        ["norisk_app.py", "--install-collector-task", "--finlai-home", r"C:\iso"]
    )
    assert rc == 0
    assert calls["finlai_home"] == r"C:\iso"


def test_install_default_kein_untrusted_override(monkeypatch) -> None:
    # Ohne Flag: Security-Gate aktiv (allow_untrusted_path=False).
    calls = {}
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        lambda **kw: calls.update(kw),
    )
    _run_collector_cli(["norisk_app.py", "--install-collector-task"])
    assert calls["allow_untrusted_path"] is False


def test_install_flag_setzt_untrusted_override(monkeypatch) -> None:
    # --allow-untrusted-collector-path -> Gate übergehen (Dev/lokaler Smoke).
    calls = {}
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        "tools.network_monitor.data.collector_task_manager.install_collector_task",
        lambda **kw: calls.update(kw),
    )
    _run_collector_cli(
        [
            "norisk_app.py",
            "--install-collector-task",
            "--allow-untrusted-collector-path",
        ]
    )
    assert calls["allow_untrusted_path"] is True


def test_run_collector_reicht_finlai_home_durch(monkeypatch) -> None:
    # Frozen-Pfad: norisk.exe --run-collector --finlai-home "<dir>" -> der Wert
    # muss an collector_main weitergereicht werden (sonst Default-Profil).
    calls = {}
    monkeypatch.setattr(
        "apps.collector_main.main",
        lambda argv: calls.update(argv=argv) or 0,
    )
    rc = _run_collector_cli(
        ["norisk.exe", "--run-collector", "--finlai-home", r"C:\iso"]
    )
    assert rc == 0
    assert calls["argv"] == ["--finlai-home", r"C:\iso"]


def test_finlai_home_from_argv_extrahiert_wert() -> None:
    from apps.norisk_app import _finlai_home_from_argv

    assert _finlai_home_from_argv(["x", "--finlai-home", "C:/p"]) == "C:/p"
    assert _finlai_home_from_argv(["x"]) is None
    # Flag ohne Wert am Ende -> None (kein IndexError).
    assert _finlai_home_from_argv(["x", "--finlai-home"]) is None
