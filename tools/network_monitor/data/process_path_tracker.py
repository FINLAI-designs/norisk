"""network_monitor.data.process_path_tracker — PID→Image-Pfad aus Kernel-Process Regel 4).

Baut aus den ``Microsoft-Windows-Kernel-Process``-ProcessStart-Events (Event 1)
eine ``pid -> image_path``-Map. Damit wird der exe-Pfad **zur Startzeit
eingefroren** (Sysmon-EID-1-Muster) — robust gegen kurzlebige Dropper, deren PID
zur Detekt-Zeit laengst weg waere. Speist die Unknown-Path-Regel (Regel 4).

Liegt in ``data/`` (Wire-Format-Konsum), pure + headless-testbar (operiert nur
auf den vom Collector durchgereichten Roh-Event-Dicts).
"""

from __future__ import annotations

from typing import Any, Final

from tools.network_monitor.data.etw_sanitize import sanitize_text

#: Event-ID „ProcessStart" des Kernel-Process-Providers.
KERNEL_PROCESS_START_EVENT_ID: Final[int] = 1
#: PID des GESTARTETEN Prozesses steht im Payload (Header-PID = Erzeuger).
_PID_KEYS: Final[tuple[str, ...]] = ("ProcessID", "ProcessId", "PID")
_IMAGE_KEYS: Final[tuple[str, ...]] = ("ImageName", "ImageFileName")
#: Obergrenze der Map (Schutz gegen unbegrenztes Wachstum; PIDs werden recycelt).
_MAX_ENTRIES: Final[int] = 50_000
#: Obergrenze fuer Image-Pfade. Reale Windows-Pfade liegen unter MAX_PATH (260),
#: erweiterte (\\?\) bis ~32k. Im elevated Collector gegen feindlich lange oder
#: steuerzeichen-behaftete Image-Namen hart geklemmt.
_MAX_IMAGE_PATH_LEN: Final[int] = 1024


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _first(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


class ProcessPathTracker:
    """Map ``pid -> image_path``, gefuettert aus Kernel-Process-ProcessStart."""

    def __init__(self) -> None:
        self._paths: dict[int, str] = {}

    def add_event(self, event_id: int, raw: dict[str, Any]) -> None:
        """Verbucht ein ProcessStart-Event; andere werden ignoriert."""
        if event_id != KERNEL_PROCESS_START_EVENT_ID:
            return
        pid = _coerce_int(_first(raw, _PID_KEYS))
        image_raw = _first(raw, _IMAGE_KEYS)
        if pid is None or not image_raw:
            return
        image = sanitize_text(image_raw, max_len=_MAX_IMAGE_PATH_LEN)
        if not image:  # nach dem Strippen leer (z. B. nur Steuerzeichen) -> kein Pfad
            return
        if len(self._paths) >= _MAX_ENTRIES:
            self._paths.clear()
        self._paths[pid] = image

    def resolve(self, pid: int) -> str:
        """Liefert den eingefrorenen Image-Pfad oder ``""`` (unbekannt)."""
        return self._paths.get(pid, "")
