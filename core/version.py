"""core/version.py — Single source of truth für alle App-Versionen.

Alle anderen Module die die App-Version benötigen importieren von hier.
``__build_date__`` wird VOR einem Release-Build manuell aktualisiert.
(Das automatische Überschreiben durch build.py stammte aus dem Monorepo;
das heutige build.py ist ein reiner Spec-Helfer ohne Pipeline — ein
Auto-Stamping kommt ggf. mit Batch 3 zurück.)

Verwendung:
    from core.version import __version__, get_version_info

Author: Patrick Riederich
"""

from __future__ import annotations

__version__ = "1.0.0"
__build_date__ = "2026-04-12"


def get_version_info(app_id: str = "") -> dict[str, str]:
    """Gibt strukturierte Versions-Informationen zurück.

    Args:
        app_id: Optionaler App-Bezeichner (z.B. ``"finlai"``, ``"automate"``).

    Returns:
        Dict mit den Schlüsseln ``"version"``, ``"build_date"`` und ``"app_id"``.
    """
    return {
        "version": __version__,
        "build_date": __build_date__,
        "app_id": app_id,
    }
