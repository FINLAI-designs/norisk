"""batch_upgrade_service — Orchestrator fuer sequentielle Patch-Upgrades.

 / PM-2.x Stop-Step B. Nimmt eine Liste von
:class:`core.patch_upgrade.UpgradeRequest`, ruft fuer jeden Eintrag
:meth:`WingetUpgradeExecutor.upgrade` auf, persistiert das Ergebnis im
:class:`UpgradeHistoryRepository` und meldet Fortschritt ueber Callbacks
an den GUI-Worker (Stop-Step C).

Designziele:

* **Sequentiell, nicht parallel** — winget verriegelt eh die System-Paket-DB
  (parallele Aufrufe waeren entweder serialisiert oder konfliktreich).
  Plus: sequentiell ist im Live-Log lesbar.
* **Cancellable** — der Aufrufer kann via ``should_cancel``-Callback
  signalisieren, dass abgebrochen werden soll. Aktuelle Aktion laeuft
  fertig (winget hat keinen sauberen Stop), restliche Queue wird
  uebersprungen mit Status:attr:`UpgradeStatus.SKIPPED`.
* **Fehler-tolerant** — eine fehlgeschlagene Aktion stoppt die Batch
  nicht; Audit bleibt vollstaendig.
* **Headless-testbar** — keine PySide6-Imports.

Schichtzugehoerigkeit: ``application/`` (orchestriert ``core/``-Executor
+ ``data/``-Repository, kein GUI).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from core.logger import get_logger
from core.patch_id_utils import is_synthetic_id
from core.patch_upgrade import (
    UpgradeRequest,
    UpgradeResult,
    UpgradeStatus,
    WingetUpgradeExecutor,
)
from tools.patch_monitor.data.upgrade_history_repository import (
    UpgradeHistoryRepository,
)

log = get_logger(__name__)


#: Callback-Signatur fuer "Aktion startet". ``(index, total, request)`` —
#: index ist 1-basiert.
StartCallback = Callable[[int, int, UpgradeRequest], None]

#: Callback-Signatur fuer "Aktion fertig". ``(index, total, request, result)``.
FinishCallback = Callable[[int, int, UpgradeRequest, UpgradeResult], None]

#: Callback-Signatur fuer Cancel-Check — wird zwischen jedem Item geprueft.
CancelCheck = Callable[[], bool]


@dataclass(frozen=True)
class BatchSummary:
    """Aggregierte Statistik nach Batch-Ende.

    Attributes:
        total: Anzahl der ursspruenglich angeforderten Items.
        succeeded: Items mit:attr:`UpgradeStatus.SUCCESS`.
        failed: Items mit:attr:`UpgradeStatus.FAILED`.
        timed_out: Items mit:attr:`UpgradeStatus.TIMEOUT`.
        skipped: Items mit:attr:`UpgradeStatus.SKIPPED` (Cancel-Effekt).
        results: Pro-Item-Ergebnis in der Original-Reihenfolge.
    """

    total: int
    succeeded: int
    failed: int
    timed_out: int
    skipped: int
    results: list[UpgradeResult]


class BatchUpgradeService:
    """Orchestriert N Upgrades sequentiell mit Audit + Progress + Cancel."""

    def __init__(
        self,
        executor: WingetUpgradeExecutor | None = None,
        repository: UpgradeHistoryRepository | None = None,
    ) -> None:
        """Initialisiert den Service.

        Default-Konstruktion ohne Argumente baut Executor + Repository
        mit Defaults — Tests injizieren beide Mocks.

        Args:
            executor: Optional vorbereiteter
:class:`WingetUpgradeExecutor`. Default: neu konstruiert.
            repository: Optional vorbereitetes
:class:`UpgradeHistoryRepository`. Default: neu konstruiert
                — legt die DB-Datei beim ersten Schreib-Zugriff an.
        """
        self._executor = executor or WingetUpgradeExecutor()
        self._repository = repository or UpgradeHistoryRepository()

    def upgrade_batch(
        self,
        requests: list[UpgradeRequest],
        *,
        on_start: StartCallback | None = None,
        on_finish: FinishCallback | None = None,
        should_cancel: CancelCheck | None = None,
    ) -> BatchSummary:
        """Fuehrt die Liste der Upgrade-Requests sequentiell aus.

        Garantie: wirft **keine** Exception nach aussen. Jede einzelne
        Aktion endet mit einem:class:`UpgradeResult` — Executor-
        Exceptions werden als FAILED-Result mit ``error``-Text gemeldet,
        Repository-Exceptions werden geloggt aber das Result wird trotzdem
        im:attr:`BatchSummary.results` zurueckgegeben (Audit-Lecke nur
        in Logs, nie ein Crash).

        Args:
            requests: Die auszufuehrenden Upgrade-Aktionen in der
                gewuenschten Reihenfolge.
            on_start: Optionaler Callback vor jedem Item.
            on_finish: Optionaler Callback nach jedem Item.
            should_cancel: Optionaler Callback. Wenn er ``True`` liefert,
                wird die noch ausstehende Queue mit
:attr:`UpgradeStatus.SKIPPED` markiert und der Batch
                vorzeitig beendet.

        Returns:
:class:`BatchSummary` mit Zaehlern + Pro-Item-Ergebnis.
        """
        total = len(requests)
        results: list[UpgradeResult] = []
        cancelled = False

        for index, request in enumerate(requests, start=1):
            if cancelled or (should_cancel and should_cancel()):
                cancelled = True
                skipped = self._make_skipped_result(request)
                results.append(skipped)
                if on_finish is not None:
                    on_finish(index, total, request, skipped)
                continue

            if on_start is not None:
                on_start(index, total, request)

            result = self._run_single(request)
            self._record_safe(request, result)
            results.append(result)

            if on_finish is not None:
                on_finish(index, total, request, result)

        return _build_summary(total, results)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_single(self, request: UpgradeRequest) -> UpgradeResult:
        """Fuehrt eine einzelne Upgrade-Aktion aus und faengt Exceptions.

        Dispatch nach ``winget_id`` vs. ``store_id`` — beide Felder
        sind ``str | None``, exactly one ist gesetzt. Catalog → ``upgrade``,
        Store → ``upgrade_msstore``. Beide Felder ``None`` (Programmierfehler
        vom Caller) → defensives FAILED-Result.
        """
        package_id = request.package_id
        # Defense-in-depth: synthetische Ids (Registry-/MSIX-Apps,
        # ``regid:``/``msix:``) duerfen NIE an den Executor — winget kennt
        # sie nicht. Der Aufrufer (GUI) filtert sie via _is_upgradeable
        # vorab heraus; landet trotzdem eine in der Queue, ueberspringen
        # wir sie hier SKIPPED, ohne den Executor zu rufen.
        if is_synthetic_id(request.winget_id):
            log.warning(
                "Synthetische Id im Batch uebersprungen (display_name=%s) — "
                "Registry-/MSIX-Apps sind nicht via winget upgradebar.",
                request.display_name,
            )
            return UpgradeResult(
                winget_id=package_id,
                status=UpgradeStatus.SKIPPED,
                exit_code=None,
                duration_ms=0,
                stdout="",
                stderr="",
                error="Registry-/MSIX-App ist nicht via winget upgradebar",
            )
        try:
            if request.store_id is not None:
                return self._executor.upgrade_msstore(request.store_id)
            if request.winget_id is not None:
                return self._executor.upgrade(request.winget_id)
            # Beide None → unerwartet, sollte vom UI ausgefiltert sein
            log.warning(
                "UpgradeRequest ohne winget_id und ohne store_id — "
                "Item wird ausgelassen: display_name=%s",
                request.display_name,
            )
            return UpgradeResult(
                winget_id=package_id,
                status=UpgradeStatus.FAILED,
                exit_code=None,
                duration_ms=0,
                stdout="",
                stderr="",
                error="UpgradeRequest ohne Package-Id (winget_id/store_id beide None)",
            )
        except Exception as exc:  # noqa: BLE001 — Batch darf nie crashen
            log.warning(
                "Upgrade-Aufruf wirft Exception: id=%s type=%s",
                package_id,
                type(exc).__name__,
            )
            return UpgradeResult(
                winget_id=package_id,
                status=UpgradeStatus.FAILED,
                exit_code=None,
                duration_ms=0,
                stdout="",
                stderr="",
                error=f"{type(exc).__name__}: {exc}",
            )

    def _record_safe(self, request: UpgradeRequest, result: UpgradeResult) -> None:
        """Persistiert den Versuch — Repository-Fehler crashen nicht.

        ``package_id`` faellt auf store_id zurueck wenn winget_id
        None ist (Repository-Schema hat nur eine ``winget_id``-Spalte,
        die wir als generische Package-Id-Spalte nutzen).
        """
        try:
            self._repository.record(
                winget_id=request.package_id,
                display_name=request.display_name,
                version_from=request.version_from,
                version_to=request.version_to,
                result=result,
            )
        except Exception as exc:  # noqa: BLE001 — Audit darf nie crashen
            log.exception(
                "Audit-Record fehlgeschlagen: id=%s err=%s",
                request.package_id,
                exc,
            )

    @staticmethod
    def _make_skipped_result(request: UpgradeRequest) -> UpgradeResult:
        """Baut ein SKIPPED-Result fuer Items, die nach Cancel weggefallen sind."""
        return UpgradeResult(
            winget_id=request.package_id,
            status=UpgradeStatus.SKIPPED,
            exit_code=None,
            duration_ms=0,
            stdout="",
            stderr="",
            error="Batch abgebrochen",
        )


def _build_summary(total: int, results: list[UpgradeResult]) -> BatchSummary:
    """Aggregiert die Pro-Item-Results zu einer Statistik."""
    succeeded = sum(1 for r in results if r.status is UpgradeStatus.SUCCESS)
    failed = sum(1 for r in results if r.status is UpgradeStatus.FAILED)
    timed_out = sum(1 for r in results if r.status is UpgradeStatus.TIMEOUT)
    skipped = sum(1 for r in results if r.status is UpgradeStatus.SKIPPED)
    return BatchSummary(
        total=total,
        succeeded=succeeded,
        failed=failed,
        timed_out=timed_out,
        skipped=skipped,
        results=results,
    )


__all__ = [
    "BatchSummary",
    "BatchUpgradeService",
    "CancelCheck",
    "FinishCallback",
    "StartCallback",
]
