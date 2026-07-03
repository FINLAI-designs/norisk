"""
apply_worker — Qt-Worker fuer den elevated Apply-Round-Trip.

Wrappt:func:`tools.system_tuner.application.elevated_round_trip.
request_elevated_apply` in einem ``QObject`` (moveToThread-Muster wie
``core.scan_worker``), damit die UI waehrend UAC-Abfrage + Poll nicht blockiert.

Die eigentliche Apply-Funktion ist injizierbar (``apply_fn``) — Tests reichen
einen Fake; Produktion nutzt den echten Round-Trip.

Schicht: ``gui/`` — importiert nur application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal, Slot

from core.logger import get_logger

log = get_logger(__name__)


def _default_apply(tweak_ids: list[str]) -> object:
    from tools.system_tuner.application.elevated_round_trip import (  # noqa: PLC0415
        request_elevated_apply,
    )

    return request_elevated_apply(tweak_ids)


class ApplyWorker(QObject):
    """Asynchroner elevated-Apply-Worker.

    Signals:
        done(object)::class:`BatchResult` (oder ``None``, wenn UAC abgelehnt /
            Timeout). Genau eines von ``done``/``failed`` wird emittiert.
        failed(str): unerwartete Exception (Safety-Net — der Round-Trip selbst
            ist fail-safe).
    """

    done = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        tweak_ids: list[str],
        *,
        apply_fn: Callable[[list[str]], object] | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._ids = list(tweak_ids)
        self._apply_fn = apply_fn or _default_apply

    @Slot()
    def run(self) -> None:
        """Fuehrt den Apply-Round-Trip aus und emittiert genau ein Signal."""
        try:
            result = self._apply_fn(self._ids)
            self.done.emit(result)
        except Exception as exc:  # noqa: BLE001 — Worker darf nie crashen
            log.exception("ApplyWorker.run unerwartete Exception: %s", exc)
            self.failed.emit(str(exc))


__all__ = ["ApplyWorker"]
