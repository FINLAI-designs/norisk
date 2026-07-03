"""
patch_service — Pipeline-Service fuer den Patch-Monitor-Scan.

PM-1.6. Glue-Layer, der alle bisherigen PM-Bausteine
verbindet:

    collect_all (PM-1.1a)
      → ChannelResolver.resolve_batch (PM-1.4)
        → CveMatcher.enrich_decision (PM-1.5)
          → list[PatchScanResult]

Wird von PM-1.7 (UI Patch-Konsole) ueber den:class:`ScanWorker`
(PM-1.1b) konsumiert; der Worker delegiert seine Welle 3 an
:meth:`PatchService.scan` mit ``progress_cb=self._emit_progress``
und feuert pro Item ein ``scan_progress``-Signal.

**Garantie:**:meth:`PatchService.scan` wirft NIE eine Exception
nach aussen.

* ``collect_all``-Crash → leere Liste + Log-Error.
* Per-Item-Exception in ``enrich_decision`` → Item ueberspringen
  + Log-Warning, Scan laeuft weiter.
"""

from __future__ import annotations

from collections.abc import Callable

from core.logger import get_logger
from core.patch_channel_resolver import ChannelDecision, ChannelResolver
from core.patch_collector import collect_all
from core.patch_cve_matcher import CveMatcher
from core.patch_result import PatchScanResult

log = get_logger(__name__)

ProgressCallback = Callable[[int, int], None]
"""``(current, total)`` — current ist 1-basiert."""


class PatchService:
    """Orchestriert Sammlung + Resolver + Enrichment zu
:class:`PatchScanResult`-Liste.

    Standard-Konstruktion ohne Argumente verwendet die Default-
    Resolver/Matcher. Tests injizieren Mocks fuer beide.
    """

    def __init__(
        self,
        resolver: ChannelResolver | None = None,
        matcher: CveMatcher | None = None,
    ) -> None:
        """Initialisiert die Pipeline.

        Args:
            resolver: Optional vorbereiteter
:class:`ChannelResolver`. Default: neu konstruiert
                (was wiederum eine Default-:class:`PolicyDB`
                anlegt — SQLCipher-DB-Pfad).
            matcher: Optional vorbereiteter:class:`CveMatcher`.
                Default: neu konstruiert (mit lazy
                NvdService-Initialisierung — kein Netzwerk-Call
                bevor:meth:`scan` aufgerufen wird).
        """
        self._resolver = resolver or ChannelResolver()
        self._matcher = matcher or CveMatcher()

    def scan(
        self,
        progress_cb: ProgressCallback | None = None,
    ) -> list[PatchScanResult]:
        """Fuehrt einen vollstaendigen Patch-Scan durch.

        Pipeline (mit Per-Stage-Fehler-Toleranz):

        1. ``collect_all`` — Inventar sammeln. Bei Exception:
           leere Liste zurueck.
        2. ``ChannelResolver.resolve_batch`` — pro Item eine
:class:`ChannelDecision`. ChannelResolver ist selbst
           fail-open (siehe sein Modul-Docstring).
        3. ``CveMatcher.enrich_decision`` pro Decision. Per-Item-
           Exception → Item ueberspringen, Scan laeuft weiter.

        Args:
            progress_cb: Optionaler Fortschritts-Callback
                ``(current, total)``. Wird **pro Item** in Welle 3
                gefeuert (1-basiert). NICHT mit ``(0, total)`` am
                Anfang gefeuert — das wuerde der UI nur einen
                leeren Tick liefern.

        Returns:
            Liste der:class:`PatchScanResult`-Objekte. Bei
            Sammler-Crash: ``[]``.
        """
        try:
            items = collect_all()
        except Exception as e:  # noqa: BLE001 — fail-open
            log.exception(
                "PatchService.scan: collect_all crashte (%s) — leere Liste",
                e,
            )
            return []

        if not items:
            return []

        # PM-1.8 + Bug-3-Fix C-2 +:
        # verfuegbare Updates kommen ausschliesslich aus den
        # SoftwareItems selbst — `item.latest_available` ist auf dem
        # Module-Pfad (Microsoft.WinGet.Client) befuellt. Tabular-Items
        # haben es als ``None``, fallen damit aus dem Lookup heraus
        # (Tabular-User sehen Inventar, aber keine Update-Spalte —
        # Onboarding-Dialog draengt sie auf den Modul-Pfad).
        available_dict = {
            item.winget_id: item.latest_available
            for item in items
            if item.winget_id and item.latest_available
        }

        decisions: list[ChannelDecision] = self._resolver.resolve_batch(items)

        results: list[PatchScanResult] = []
        total = len(decisions)
        for idx, decision in enumerate(decisions, start=1):
            try:
                avail = (
                    available_dict.get(decision.item.winget_id)
                    if decision.item.winget_id
                    else None
                )
                result = self._matcher.enrich_decision(
                    decision, available_version=avail
                )
                results.append(result)
            except Exception as e:  # noqa: BLE001 — per-item fail-open
                log.warning(
                    "PatchService.scan: enrich_decision fuer %r "
                    "fehlgeschlagen (%s) — Item uebersprungen, "
                    "Scan laeuft weiter.",
                    decision.item.name, e,
                )
            if progress_cb is not None:
                try:
                    progress_cb(idx, total)
                except Exception:  # noqa: BLE001 — Callback-Fehler isolieren
                    log.exception(
                        "PatchService.scan: progress_cb crashte — "
                        "ignoriere und mache weiter."
                    )

        return results

    def scan_summary(self) -> dict:
        """Convenience-Wrapper: Scan + aggregierte Zaehler.

        Returns:
            Dictionary mit Keys: ``total``, ``urgent``, ``update``,
            ``up_to_date``, ``notify_only``, ``with_cves``,
            ``results``. ``results`` ist die volle
:class:`PatchScanResult`-Liste; die Zaehler sind
            Convenience fuer Dashboards/Logs.
        """
        results = self.scan()
        return {
            "total": len(results),
            "urgent": sum(
                1 for r in results if r.recommendation == "update_urgent"
            ),
            "update": sum(
                1 for r in results if r.recommendation == "update"
            ),
            "up_to_date": sum(
                1 for r in results if r.recommendation == "up_to_date"
            ),
            "notify_only": sum(
                1 for r in results if r.recommendation == "notify_only"
            ),
            "with_cves": sum(1 for r in results if r.cve_ids),
            "results": results,
        }
