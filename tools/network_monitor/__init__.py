"""Netzwerkmonitor — Live-Bandbreite, aktive Verbindungen, Suspicious-Detection (Pro).

Lazy Paket-Re-Export (PEP 562): ``NetworkMonitorTool`` wird erst beim Attribut-
Zugriff importiert, NICHT beim Import des Pakets. So zieht der Import eines
headless-Submoduls (z. B. ``tools.network_monitor.data.etw_event_normalizer`` im
ETW-Collector, ``apps/collector_main.py``) nicht mehr die GUI/Qt-Kette herein
(``.tool`` → ``core.base_tool`` → ``PySide6.QtWidgets``).

Hintergrund F-C, Build-Spike 2026-06-09): Der frühere eager Re-Export
``from.tool import NetworkMonitorTool`` machte jeden Submodul-Import des Pakets
Qt-abhängig — die headless Collector-Exe hätte das gesamte Qt bündeln müssen
(unnötig groß + größere Angriffsfläche). Der Lazy-Export hält die Collector-Exe
Qt-frei; der öffentliche Zugriff ``from tools.network_monitor import
NetworkMonitorTool`` bleibt unverändert möglich (PEP 562 ``__getattr__``).
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

__all__ = ["NetworkMonitorTool"]

if TYPE_CHECKING:  # nur für Typprüfer/IDE — kein Laufzeit-Import (Qt-frei)
    from .tool import NetworkMonitorTool


def __getattr__(name: str) -> object:
    """Löst Paket-Symbole lazy aus ``.tool`` auf (PEP 562).

    Auflösung über ``__all__`` (statt eines hartkodierten Einzelnamens), damit
    ein künftig ergänztes öffentliches Symbol nicht still durchfällt — die
    einzige Pflege bleibt ``__all__``.

    Args:
        name: Angefragter Attributname auf Paket-Ebene.

    Returns:
        Das aus ``.tool`` aufgelöste Symbol.

    Raises:
        AttributeError: Wenn ``name`` kein in ``__all__`` geführtes Paket-Symbol
            ist — mit der von Python erwarteten Standard-Meldung, damit
            ``hasattr`` und ``from … import …`` sich regulär verhalten.
    """
    if name in __all__:
        # Lazy: erst hier wird ``.tool`` (und damit die Qt-Kette) importiert,
        # nicht beim Paket-Import — so bleiben die Submodul-Importe des headless
        # Collectors Qt-frei. ``import_module`` ist stdlib (Qt-frei).
        return getattr(import_module(f"{__name__}.tool"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
