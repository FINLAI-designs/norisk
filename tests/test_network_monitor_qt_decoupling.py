"""Regressionstests für das Qt-Decoupling des network_monitor-Pakets F-C-1).

Der headless ETW-Collector (``apps/collector_main.py``) importiert
network_monitor-Submodule (``data``/``application``). Vor zog jeder solche
Import über das eager Paket-``__init__`` (``from.tool import NetworkMonitorTool``)
die gesamte Qt-GUI-Kette herein (``.tool`` → ``core.base_tool`` →
``PySide6.QtWidgets``) — die headless Collector-Exe hätte ganz Qt bündeln müssen
(Build-Spike-Befund 2026-06-09).

Diese Tests verankern strukturell, dass
1. der Import des Collector-Einstiegspunkts und einzelner Submodule **kein**
   PySide6 mitlädt, und
2. das öffentliche Tool-Symbol trotz Lazy-Import unverändert auflösbar bleibt.

Die Import-Isolations-Prüfungen laufen in einem **Subprozess**: der pytest-Prozess
selbst hat (über GUI-Tests/conftest) PySide6 längst geladen, eine In-Process-
``sys.modules``-Prüfung wäre damit wertlos.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _qt_modules_after_import(import_stmt: str) -> subprocess.CompletedProcess[str]:
    """Führt ``import_stmt`` in einem frischen Interpreter aus und meldet geladene PySide6-Module.

    Args:
        import_stmt: Eine oder mehrere Import-/Assert-Zeilen (mit ``\\n`` getrennt).

    Returns:
        Das abgeschlossene Subprozess-Ergebnis; ``stdout`` enthält die Zeile
        ``QT_LOADED:<komma-getrennte PySide6-Module>`` (leer = Qt-frei).
    """
    code = (
        "import sys\n"
        f"{import_stmt}\n"
        "loaded = sorted(m for m in sys.modules "
        "if m == 'PySide6' or m.startswith('PySide6.'))\n"
        "print('QT_LOADED:' + ','.join(loaded))\n"
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        # PYTHONPATH explizit setzen statt allein auf das implizite sys.path-''
        # (cwd) bei ``-c`` zu bauen — robust auch, falls die Suite je außerhalb
        # des Repo-Roots oder gegen ein installiertes Layout läuft.
        env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _assert_qt_free(result: subprocess.CompletedProcess[str], *, what: str) -> None:
    """Bestätigt, dass der Subprozess erfolgreich lief und PySide6 nicht lud."""
    assert result.returncode == 0, f"Import von {what} fehlgeschlagen:\n{result.stderr}"
    qt_line = next(
        (ln for ln in result.stdout.splitlines() if ln.startswith("QT_LOADED:")),
        "<keine QT_LOADED-Zeile>",
    )
    assert qt_line == "QT_LOADED:", (
        f"{what} hat PySide6 mitgeladen — das Qt-Decoupling des "
        f"network_monitor-__init__ ist gebrochen. {qt_line}\n{result.stderr}"
    )


def test_collector_entrypoint_import_is_qt_free() -> None:
    """``import apps.collector_main`` darf PySide6 NICHT mitladen (headless Collector).

    Primärer End-to-End-Wächter: prüft den realen Collector-Importgraphen (nicht
    nur ein handverlesenes Submodul). Wird hier künftig versehentlich ein
    Qt-behaftetes Modul eingezogen, schlägt dieser Test rot an.
    """
    _assert_qt_free(
        _qt_modules_after_import("import apps.collector_main"),
        what="apps.collector_main",
    )


def test_collector_path_submodule_import_is_qt_free() -> None:
    """Import eines Collector-Pfad-Submoduls triggert das eager Tool-/Qt-Re-Export nicht.

    Bewacht gezielt das Lazy-``__init__`` (kein eager ``.tool``-Pull) anhand eines
    Moduls, das der echte Collector importiert (``apps/collector_main.py:44``).
    Es ist KEINE Aussage über die gesamte data-Schicht: reine GUI-Submodule wie
    ``data/monitor_worker.py`` ziehen legitim Qt (``QThread``/``Signal``) und
    werden vom headless Collector bewusst nicht importiert. Der echte End-to-End-
    Wächter über den ganzen Collector-Importgraphen ist
:func:`test_collector_entrypoint_import_is_qt_free`.
    """
    _assert_qt_free(
        _qt_modules_after_import(
            "import tools.network_monitor.data.etw_event_normalizer"
        ),
        what="tools.network_monitor.data.etw_event_normalizer",
    )


def test_package_import_does_not_eager_load_tool_module() -> None:
    """Der reine Paket-Import darf das ``.tool``-Submodul (Qt) nicht eager laden."""
    result = _qt_modules_after_import(
        "import tools.network_monitor as nm\n"
        "assert 'tools.network_monitor.tool' not in sys.modules, "
        "'tool-Submodul eager geladen — Lazy-Contract verletzt'"
    )
    assert result.returncode == 0, (
        f"Paket-Import verletzte den Lazy-Contract:\n{result.stderr}"
    )


def test_public_tool_symbol_resolves_lazily() -> None:
    """``from tools.network_monitor import NetworkMonitorTool`` bleibt funktionsfähig (PEP 562)."""
    import tools.network_monitor as nm

    assert "NetworkMonitorTool" in nm.__all__
    tool_cls = nm.NetworkMonitorTool  # löst __getattr__ aus → lazy.tool-Import
    assert isinstance(tool_cls, type)
    assert tool_cls.__name__ == "NetworkMonitorTool"


def test_unknown_attribute_raises_attribute_error() -> None:
    """Das Lazy-``__getattr__`` wirft für unbekannte Namen sauber ``AttributeError``."""
    import tools.network_monitor as nm

    with pytest.raises(AttributeError):
        _ = nm.DoesNotExist
