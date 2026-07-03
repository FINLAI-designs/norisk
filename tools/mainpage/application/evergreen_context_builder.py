"""
evergreen_context_builder — Application-Adapter zwischen Tool-States und
:class:`EvergreenGatingContext`.

Sammelt den State-Snapshot fuer die Evergreen-Predicates aus:

    * ``core.registry.last_scan_registry`` — letzter Scan pro Tool.
    * ``PatchInventoryService`` — letzter Patch-Vollscan.
    * ``HardeningScoreRepository`` — letzter persistierter Score.

Lebt in ``application/``, weil das Sammeln Cross-Tool ist und die GUI
nicht direkt auf ``data/``-Repositories zugreifen darf
(Hexagonal-Contract).

Jeder Read ist defensiv — Exception → ``None``, der Predicate-Konvention
folgend (``None`` zeigt das Template).

Schichtzugehoerigkeit: ``application/`` — darf ``data/`` lesen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.mainpage.application.evergreen_provider import (
    EvergreenGatingContext,
)

log = get_logger(__name__)


def build_evergreen_context(
    *,
    hardening_target_name: str = "self",
) -> EvergreenGatingContext:
    """Baut den Context fuer:func:`get_evergreens`.

    Args:
        hardening_target_name: ``target_name`` fuer den Hardening-Score-
            Lookup. Default ``"self"`` — der eigene System-Score.

    Returns:
:class:`EvergreenGatingContext` mit allen verfuegbaren Feldern.
        Felder bei Read-Fehler bleiben ``None``.
    """
    return EvergreenGatingContext(
        last_system_scan=_safe_last_scan("system_scanner"),
        last_patch_scan=_safe_patch_last_scan(),
        last_csaf_check=_safe_last_scan("csaf_advisor"),
        last_techstack_change=_safe_techstack_change(),
        hardening_score=_safe_hardening_score(hardening_target_name),
    )


def _safe_last_scan(tool_name: str):  # noqa: ANN202
    try:
        from core.registry.last_scan_registry import (  # noqa: PLC0415
            get_last_scan,
        )

        return get_last_scan(tool_name)
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "EvergreenContext: get_last_scan(%s) warf %s",
            tool_name, type(exc).__name__,
        )
        return None


def _safe_patch_last_scan():  # noqa: ANN202
    """Letzter Patch-Vollscan via PatchInventoryService."""
    try:
        from tools.patch_monitor.application.patch_inventory_service import (  # noqa: PLC0415
            PatchInventoryService,
        )

        return PatchInventoryService().get_last_full_scan_at()
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "EvergreenContext: Patch-LastScan warf %s",
            type(exc).__name__,
        )
        return None


def _safe_hardening_score(target_name: str):  # noqa: ANN202
    """Letzter persistierter Hardening-Score via HardeningScoreRepository.

    Application-Schicht darf ``data/`` lesen — der GUI-Layer bleibt sauber.
    """
    try:
        from tools.security_scoring.data.hardening_score_repository import (  # noqa: PLC0415
            HardeningScoreRepository,
        )

        repo = HardeningScoreRepository()
        history = repo.load_history(target_name=target_name, limit=1)
        if not history:
            return None
        # load_history liefert (timestamp, overall_score)-Tupel-Fix).
        return float(history[0][1])
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "EvergreenContext: Hardening-Score-Read warf %s",
            type(exc).__name__,
        )
        return None


def _safe_techstack_change():  # noqa: ANN202
    """Letzte Tech-Stack-Aenderung.

    Aktuell ``None`` als Default — Tech-Stack-Tool hat keine Last-Edit-
    API. Bei Erweiterung kann das hier nachgezogen werden ohne dass
    der Provider oder Widget angepasst werden muss.
    """
    return None


__all__ = ["build_evergreen_context"]
