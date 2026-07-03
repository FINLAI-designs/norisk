"""patch_inventory_service — Tier-Modell-Orchestrator fuer den Patch-Monitor.

 Stop-Step B. Wraps:class:`core.patch_service.PatchService` und
:class:`tools.patch_monitor.data.patch_inventory_repository.PatchInventoryRepository`
zu drei klaren Anwendungsfaellen:

1.:meth:`full_scan` (~15-20 min): kompletter Scan (Inventar + CPE + CVE)
   und vollstaendige Persistenz. Wird bei Erstinstall, monatlich oder
   manuell vom User getriggert.
2.:meth:`daily_refresh` (~30-60 s): nur ``available_versions`` aus
   winget aktualisieren + CVE-Refresh fuer Eintraege aelter als 24 h.
   Inventar selbst bleibt unangefasst.
3.:meth:`load_from_db`: rekonstruiert die ``PatchScanResult``-Liste
   ohne irgendeinen Subprocess oder Netzwerk-Call. Wird beim Tool-Open
   und beim Filter-Toggle aufgerufen.

Schichtzugehoerigkeit: ``application/`` — orchestriert ``core/``-Pipeline
+ ``data/``-Repository, kein GUI. Headless-testbar.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from core.logger import get_logger
from core.patch_channel_resolver import ChannelResolver
from core.patch_collector import SoftwareItem, collect_winget_inventory
from core.patch_custom_source import DEFAULT_PLATFORM, CustomSource, Platform
from core.patch_cve_matcher import CveMatcher
from core.patch_eol_resolver import CuratedEolResolver, IEolResolver
from core.patch_id_utils import is_synthetic_id
from core.patch_module_detection import ModuleStatus, get_winget_module_status
from core.patch_recommendation_engine import apply_recommendation_engine
from core.patch_result import PatchScanResult, _extract_vendor, _recommend
from core.patch_service import PatchService
from core.patch_strategy import PatchStrategy
from tools.csaf_advisor.domain.advisory_repository import IAdvisoryRepository
from tools.patch_monitor.application.custom_source_checker import (
    CustomSourceChecker,
    is_update_available,
)
from tools.patch_monitor.data.patch_inventory_repository import (
    AffectedCveRow,
    AvailableVersionEntry,
    CveMatchEntry,
    InventoryEntry,
    PatchInventoryRepository,
    ScanType,
)

log = get_logger(__name__)

ProgressCallback = Callable[[int, int], None]
"""``(current, total)`` — 1-basiert. Wird vom UI an PatchService durchgereicht."""


class _AdvisoryTitleAdapter:
    """ Title-Resolver-Adapter um ein ``IAdvisoryRepository``.

    Bewusst klein: nur ``get_title`` als Lookup, kein Caching (Engine
    laeuft pro Result-Set in ``load_from_db``, IDs wiederholen sich
    selten genug dass ein Cache die Komplexitaet nicht rechtfertigt).
    """

    def __init__(self, repo: IAdvisoryRepository) -> None:
        self._repo = repo

    def get_title(self, advisory_id: str) -> str | None:
        try:
            adv = self._repo.get_advisory(advisory_id)
        except Exception:  # noqa: BLE001 — Resolver darf nie crashen
            return None
        return adv.title if adv is not None else None


@dataclass(frozen=True)
class FullScanSummary:
    """Aggregat-Zaehler nach einem:meth:`full_scan`-Lauf."""

    scan_id: str
    scan_type: ScanType
    items_total: int
    items_with_updates: int
    items_with_cves: int


@dataclass(frozen=True)
class DailyRefreshSummary:
    """Aggregat-Zaehler nach einem:meth:`daily_refresh`-Lauf."""

    scan_id: str
    items_total: int
    items_with_updates: int
    cves_refreshed: int


class PatchInventoryService:
    """Persistente Patch-Datenbasis-Orchestrierung.

    Default-Konstruktion baut Repository + PatchService mit Defaults —
    Tests injizieren beide Mocks.
    """

    def __init__(
        self,
        repo: PatchInventoryRepository | None = None,
        patch_service: PatchService | None = None,
        resolver: ChannelResolver | None = None,
        matcher: CveMatcher | None = None,
        *,
        eol_resolver: IEolResolver | None = None,
        advisory_repository: IAdvisoryRepository | None = None,
        ki_todo_emitter: object | None = None,
        custom_source_checker: CustomSourceChecker | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            repo: Optional vorbereitetes Repository. Default: neu konstruiert
                (legt die EncryptedDB beim ersten Schreib-Zugriff an).
            patch_service: Optional vorbereiteter:class:`PatchService`
                fuer den Vollscan-Pfad. Default: neu konstruiert.
            resolver: Optional vorbereiteter:class:`ChannelResolver` fuer
                den Daily-Refresh-Pfad (wenn neue Items in winget auftauchen).
            matcher: Optional vorbereiteter:class:`CveMatcher` fuer den
                Daily-Refresh-Pfad (Stale-CPE-Refresh).
            eol_resolver: — Optional vorbereiteter
:class:`IEolResolver` fuer den Enrichment-Pass in
:meth:`load_from_db`. Default::class:`CuratedEolResolver`
                (offline-safe, hardcoded Liste bekannter EOL-Produkte).
            advisory_repository: — Optional vorbereiteter
:class:`IAdvisoryRepository` fuer den CSAF-Anteil der
                Recommendation-Engine. Default ``None`` → kein CSAF-
                Enrichment (Engine laeuft trotzdem, nur ohne Advisory-
                Kontext). Produktiv-Wiring injiziert via Tool-Setup
                (analog ChannelResolver).
        """
        self._repo = repo or PatchInventoryRepository()
        self._patch_service = patch_service or PatchService()
        self._resolver = resolver or ChannelResolver()
        self._matcher = matcher or CveMatcher()
        # (PM-RECOMMEND-PROD-WIRING, 2026-05-13): Enrichment-
        # Pipeline-Komponenten. Werden in ``load_from_db`` pro Result
        # aufgerufen und reichern die Basis-Recommendation um EOL- und
        # CSAF-Kontext an.
        self._eol_resolver = eol_resolver or CuratedEolResolver()
        self._advisory_repository = advisory_repository
        # Optionaler KiTodoEmitter — wird nach full_scan und
        # daily_refresh aufgerufen, damit Patch-Findings als
        # "Was tun?"-Karten auf der Mainpage landen. Default ``None`` →
        # lazy beim ersten Hook-Call. Tests injizieren einen Mock.
        self._ki_todo_emitter = ki_todo_emitter
        # Checker fuer Custom-Sources (Notify-Only). Default neu;
        # Tests injizieren ein Surrogat ohne echten HTTP-Call.
        self._custom_source_checker = custom_source_checker or CustomSourceChecker()

    # ------------------------------------------------------------------
    # Tier 1+2 — full_scan
    # ------------------------------------------------------------------

    def full_scan(
        self,
        scan_type: ScanType = "initial",
        *,
        progress_cb: ProgressCallback | None = None,
    ) -> FullScanSummary:
        """Voller Inventar+CPE+CVE-Scan + Persistenz.

        Pipeline:
            1.:meth:`PatchService.scan` — gibt eine vollstaendige
               ``list[PatchScanResult]`` zurueck (~15-20 min).
            2. Persistenz: pro Result eine ``inventory_snapshot``- und
               ``available_versions``-Zeile, pro CVE eine
               ``cve_matches``-Zeile. **Auch Registry-/MSIX-Apps** werden
               persistiert: sie tragen eine stabile synthetische
               ``winget_id`` (``regid:``/``msix:``, vergeben in
:func:`core.patch_collector.collect_all`) und erfuellen damit
               den PK-Constraint. Diese synthetischen Ids werden NIE an ein
               winget-Kommando gereicht (Gates via
:func:`core.patch_id_utils.is_synthetic_id`).
            3. Monthly-Full / Initial-Spezifikum: alle Eintraege deren
               ``winget_id`` nicht im neuen Scan vorkommen werden aus
               ``inventory_snapshot`` geloescht (deinstallierte Apps).
            4. ``scan_history``-Eintrag mit Statistik.

        Args:
            scan_type: Eins aus:data:`ScanType` — bestimmt das Audit-
                Log-Label und ob deinstallierte Apps weggeraeumt werden
                (initial/monthly_full/manual: ja; daily_refresh wird
                hier nicht verwendet).
            progress_cb: Fortschritts-Callback (1-basiert), wird an
                PatchService weitergereicht.

        Returns:
:class:`FullScanSummary` mit den persistierten Counts.
        """
        scan_id = self._repo.record_scan_start(scan_type)
        try:
            results = self._patch_service.scan(progress_cb=progress_cb)
            now = datetime.now(tz=UTC)

            seen_ids: set[str] = set()
            inventory_entries: list[InventoryEntry] = []
            available_entries: list[AvailableVersionEntry] = []
            cve_entries: list[CveMatchEntry] = []

            items_with_updates = 0
            items_with_cves = 0

            for result in results:
                # Alle Items persistieren — Registry-/MSIX-Apps tragen seit
                # den synthetischen Ids (collect_all._with_synthetic_id) eine
                # stabile ``regid:``/``msix:``-Id und erfuellen damit den
                # PK-Constraint. So bleiben sie ueber Neustart/Daily-Refresh
                # erhalten statt nur live im Scan aufzutauchen. Synthetische
                # Ids werden NIE an winget gereicht (Gates via is_synthetic_id
                # in der GUI + im Upgrade-Pfad). Ein ``winget_id is None`` kann
                # hier nicht auftreten: _with_synthetic_id weist JEDER Quelle
                # ohne echte Id eine synthetische zu — auch id-losen
                # winget-Quellen (``wgname:``, Live-Test 2026-07-01: sonst
                # verschwand z.B. KeePassXC aus der DB). Custom-Sources laufen
                # nicht ueber PatchService.scan (sie kommen erst in
                # load_from_db als notify_only-Zeilen dazu). Der Guard bleibt
                # als fail-safe Backstop.
                if result.winget_id is None:
                    log.warning(
                        "full_scan: Result ohne winget_id uebersprungen "
                        "(name=%s) — unerwartet, collect_all sollte synthetische "
                        "Ids vergeben.",
                        result.name,
                    )
                    continue
                seen_ids.add(result.winget_id)

                inventory_entries.append(
                    _result_to_inventory_entry(result, full_scan_at=now)
                )

                # available_versions: wir leiten is_update_available aus der
                # Recommendation ab — wenn update_* dann True, sonst False.
                # PatchScanResult kennt das Flag nicht direkt (es kommt
                # ueber SoftwareItem in den Scan-Pfad), aber die
                # Recommendation ist eine 1:1-Abbildung des
                # is_update_available + CVE-Schweres.
                is_update = result.recommendation in (
                    "update_urgent",
                    "update",
                    "update_available",
                )
                available_entries.append(
                    AvailableVersionEntry(
                        winget_id=result.winget_id,
                        available_version=result.available_version,
                        is_update_available=is_update,
                        last_checked_at=now,
                    )
                )
                if is_update:
                    items_with_updates += 1

                # CVE-Matches persistieren — pro CVE eine Zeile
                # NB: PatchScanResult traegt die CVE-IDs als Tuple plus
                # cvss_max + exploit_available als aggregat. Wir wollen
                # die Pro-CVE-Details — die haben wir hier nicht ohne
                # erneuten NVD-Call. Workaround: wir persistieren genau
                # ein cve_matches-Eintrag pro CVE-ID mit cvss_max als
                # Score (best-effort) und dem aggregierten exploit-Flag.
                # Saubere Loesung waere PatchScanResult um ``cve_matches``
                # zu erweitern — kann in Stop-Step E folgen.
                if result.cve_ids:
                    items_with_cves += 1
                cpe = _cpe_from_result(result)
                if cpe is not None and result.cve_ids:
                    for cve_id in result.cve_ids:
                        cve_entries.append(
                            CveMatchEntry(
                                cpe_string=cpe,
                                cve_id=cve_id,
                                cvss_score=result.cvss_max,
                                exploit_available=result.exploit_available,
                                eol=result.eol,
                                fetched_at=now,
                            )
                        )

            self._repo.upsert_inventory_batch(inventory_entries)
            self._repo.upsert_available_versions_batch(available_entries)
            self._repo.upsert_cve_matches_batch(cve_entries)

            # Monthly/Initial: deinstallierte Apps wegraeumen.
            # ``manual`` ist ein User-getriggerter Vollscan und soll auch
            # aufraeumen (User-Erwartung: "ich klicke Scan -> Stand wird
            # synchronisiert").
            if scan_type in ("initial", "monthly_full", "manual"):
                deleted = self._repo.delete_inventory_not_in(seen_ids)
                if deleted:
                    log.info(
                        "full_scan: %d deinstallierte Apps aus Inventar "
                        "entfernt (scan_type=%s).",
                        deleted,
                        scan_type,
                    )

            self._repo.record_scan_end(
                scan_id,
                items_total=len(seen_ids),
                items_with_updates=items_with_updates,
                items_with_cves=items_with_cves,
            )
            # KI-Todo-Engine fuettern. Wir nutzen ``load_from_db``
            # damit die enrichten Recommendations (eol_no_patch /
            # workaround_available / patch_with_csaf_context aus)
            # in die Findings flow — die in-memory ``results`` von
            # ``PatchService.scan`` haben nur die Basis-Recommendations.
            self._emit_patch_findings()
            return FullScanSummary(
                scan_id=scan_id,
                scan_type=scan_type,
                items_total=len(seen_ids),
                items_with_updates=items_with_updates,
                items_with_cves=items_with_cves,
            )
        except Exception as exc:
            # Auf jeden Fall den scan_history-Eintrag schliessen,
            # auch wenn der Caller den Fehler sieht.
            self._repo.record_scan_end(scan_id, error=f"{type(exc).__name__}: {exc}")
            raise

    # ------------------------------------------------------------------
    # Tier 3 — daily_refresh
    # ------------------------------------------------------------------

    def daily_refresh(
        self,
        *,
        cve_age_threshold_hours: int = 24,
    ) -> DailyRefreshSummary:
        """Schnelles Refresh: nur ``available_versions`` aus winget +
        CVE-Refresh fuer stale CPEs.

        Pipeline:
            1.:func:`collect_winget_inventory` — schneller winget-Pfad
               (~5-10 s).
            2. Update ``available_versions``-Tabelle aus
               ``item.is_update_available`` + ``item.latest_available``.
               Eintraege fuer winget_ids die im Inventar noch nicht
               existieren werden uebersprungen (sie tauchen erst beim
               naechsten Vollscan auf). **Synthetische Ids**
               (Registry-/MSIX-Apps, ``regid:``/``msix:``) werden
               ebenfalls uebersprungen — winget kennt sie nicht, ihr
               Update-Status bleibt der letzte Vollscan-Stand.
            3. ``list_stale_cpes(older_than_hours=cve_age_threshold_hours)``
               → pro stale-CPE:meth:`CveMatcher.find_for_cpe` → CVE-
               Eintraege aktualisieren.
            4. ``scan_history``-Eintrag mit ``scan_type="daily_refresh"``.

        Args:
            cve_age_threshold_hours: Eintraege deren juengster Fetch
                aelter ist gelten als stale und werden re-fetcht.

        Returns:
:class:`DailyRefreshSummary`.
        """
        scan_id = self._repo.record_scan_start("daily_refresh")
        try:
            # Winget-Reconcile: der Quick-Check gleicht die WINGET-
            # Apps mit der Live-winget-Liste ab — De- UND Neuinstallationen werden
            # erkannt. Registry-/Store-/synthetische Apps sowie CPE/CVE-Anreicherung
            # bleiben dem Vollscan vorbehalten (winget kennt jene nicht; CVE braucht
            # NVD). Bestehende winget-Apps: nur available_versions aktualisieren
            # (erhaelt cpe_string + verknuepfte cve_matches). Neue winget-Apps:
            # minimal aufnehmen (Recommendation aus dem Kanal, CVE folgt im
            # Vollscan). Nicht mehr live gelistete winget-Apps: entfernen.
            existing = self._repo.list_inventory()
            known: dict[str, InventoryEntry] = {e.winget_id: e for e in existing}

            items = collect_winget_inventory()
            now = datetime.now(tz=UTC)
            decisions = self._resolver.resolve_batch(items) if items else []
            items_with_updates = 0
            available_entries: list[AvailableVersionEntry] = []
            new_inventory: list[InventoryEntry] = []
            live_winget_ids: set[str] = set()
            for decision in decisions:
                item = decision.item
                wid = item.winget_id
                if wid is None or is_synthetic_id(wid):
                    continue
                live_winget_ids.add(wid)
                if item.is_update_available:
                    items_with_updates += 1
                available_entries.append(
                    AvailableVersionEntry(
                        winget_id=wid,
                        available_version=item.latest_available,
                        is_update_available=item.is_update_available,
                        last_checked_at=now,
                    )
                )
                if wid not in known:
                    # NEU installierte winget-App: minimal aufnehmen. Ohne CVEs →
                    # Recommendation ergibt sich aus dem (Default-)Kanal; die
                    # CVE-/CPE-Anreicherung liefert der naechste Vollscan nach.
                    result = PatchScanResult.from_decision_and_cves(
                        decision, cves=[], available_version=item.latest_available
                    )
                    new_inventory.append(
                        _result_to_inventory_entry(result, full_scan_at=now)
                    )
            if new_inventory:
                self._repo.upsert_inventory_batch(new_inventory)
            self._repo.upsert_available_versions_batch(available_entries)

            # Phantom-Cleanup: winget-Apps, die NICHT mehr in der Live-Liste
            # stehen, sind deinstalliert → aus dem Inventar entfernen. Registry-/
            # Store-/synthetische Apps (winget kennt sie nicht) bleiben geschuetzt.
            # NUR wenn winget ueberhaupt etwas lieferte — eine leere Liste ist ein
            # winget-Fehler und darf NICHT das ganze winget-Inventar loeschen.
            deleted = 0
            if items:
                keep = live_winget_ids | {
                    wid
                    for wid, e in known.items()
                    if wid is not None
                    and (e.source != "winget" or is_synthetic_id(wid))
                }
                deleted = self._repo.delete_inventory_not_in(keep)
                if deleted:
                    log.info(
                        "daily_refresh: %d nicht mehr installierte winget-App(s) "
                        "aus dem Inventar entfernt.",
                        deleted,
                    )

            # CVE-Refresh fuer stale CPEs.
            stale_cpes = self._repo.list_stale_cpes(
                older_than_hours=cve_age_threshold_hours
            )
            cves_refreshed = 0
            for cpe in stale_cpes:
                try:
                    cve_matches = self._matcher.get_cves(cpe)
                except Exception as exc:  # noqa: BLE001 — fail-open
                    log.warning(
                        "daily_refresh: CVE-Refresh fuer %s fehlgeschlagen "
                        "(%s) — uebersprungen.",
                        cpe,
                        type(exc).__name__,
                    )
                    continue
                cve_entries = [
                    CveMatchEntry(
                        cpe_string=cpe,
                        cve_id=m.cve_id,
                        cvss_score=m.cvss_score,
                        exploit_available=m.exploit_available,
                        eol=False,
                        fetched_at=now,
                    )
                    for m in cve_matches
                ]
                self._repo.upsert_cve_matches_batch(cve_entries)
                cves_refreshed += len(cve_entries)

            self._repo.record_scan_end(
                scan_id,
                items_total=len(available_entries),
                items_with_updates=items_with_updates,
            )
            # Custom-Sources im selben Refresh-Worker mitpruefen
            # (Netzwerk-Calls). Defensiv — ein Fehler hier darf den
            # winget-Refresh nicht entwerten.
            try:
                self.check_custom_sources()
            except Exception as exc:  # noqa: BLE001 — Custom-Check ist best-effort
                log.warning(
                    "daily_refresh: check_custom_sources fehlgeschlagen: %s",
                    type(exc).__name__,
                )
            # KI-Todo-Engine auch nach daily_refresh fuettern —
            # neue CVE-Matches koennen Recommendations veraendern
            # (z. B. von ``update_available`` → ``update_urgent``).
            self._emit_patch_findings()
            return DailyRefreshSummary(
                scan_id=scan_id,
                items_total=len(available_entries),
                items_with_updates=items_with_updates,
                cves_refreshed=cves_refreshed,
            )
        except Exception as exc:
            self._repo.record_scan_end(scan_id, error=f"{type(exc).__name__}: {exc}")
            raise

    # ------------------------------------------------------------------
    # KI-Todo-Emitter-Hook
    # ------------------------------------------------------------------

    def _emit_patch_findings(self) -> None:
        """Liest die enriched Results aus der DB + emittiert KI-Todo-Findings.

        Wird nach:meth:`full_scan` und:meth:`daily_refresh` aufgerufen.
        Lazy-Init des Emitters; fail-soft (Hook-Exception darf den
        Scan-Pfad nicht crashen — KI-Todo-Generierung ist nicht
        wert-kritisch fuer die Patch-Persistenz).
        """
        try:
            from tools.patch_monitor.application.storytelling_adapter import (  # noqa: PLC0415
                TOOL_NAME,
                patch_results_to_findings,
            )

            results = self.load_from_db()
            findings = patch_results_to_findings(results)
            # Der Fall "alle Updates installiert" (leere Findings,
            # aber gefülltes Inventar) muss die Reconciliation erreichen,
            # damit offene Patch-Tasks automatisch schließen.
            #
            # Reconcile-Vertrauens-Guard (Review-P1): Auto-Erledigung NUR
            # wenn der Bestand vertrauenswürdig ist —
            # (a) Inventar nicht leer: ein leeres ``results`` bedeutet
            # Collector-Crash (PatchService.scan ist fail-open ``[]``)
            # oder Frisch-DB, NICHT "alles installiert";
            # (b) winget-PowerShell-Modul aktiv: der Tabular-Fallback
            # liefert KEIN ``is_update_available`` (Default False) —
            # alle Update-Findings verschwänden scheinbar.
            # Ohne Reconcile bleibt das alte Anlege-Verhalten (kein
            # falsches Massen-Erledigen, nur kein Auto-Abschluss).
            module_ok = get_winget_module_status().status == ModuleStatus.AVAILABLE
            reconcile = TOOL_NAME if (results and module_ok) else None
            if not findings and reconcile is None:
                return
            emitter = self._ki_todo_emitter
            if emitter is None:
                from core.storytelling.ki_todo_emitter import (  # noqa: PLC0415
                    KiTodoEmitter,
                )

                emitter = KiTodoEmitter()
                self._ki_todo_emitter = emitter
            emitter.emit(findings, reconcile_tool=reconcile)
        except Exception as exc:  # noqa: BLE001 — Hook darf den Scan nicht brechen
            log.warning(
                "PatchInventoryService._emit_patch_findings: KI-Todo-Hook "
                "fehlgeschlagen (%s).",
                type(exc).__name__,
            )

    # ------------------------------------------------------------------
    # UI-Pfad — Patch-Strategie
    # ------------------------------------------------------------------

    def set_strategy(self, winget_id: str, strategy: PatchStrategy | str) -> bool:
        """Persistiert die user-gewaehlte Patch-Strategie einer App.

        Application-Fassade fuer das GUI — haelt den Hexagonal-Contract
        (``gui`` ruft ``application``, nicht direkt ``data``). Delegiert an
:meth:`PatchInventoryRepository.update_strategy`.

        Args:
            winget_id: Identifiziert die Inventar-Zeile (Catalog-Apps; Items
                ohne ``winget_id`` haben keine Strategie und werden vom GUI
                gar nicht erst mit Dropdown versehen).
            strategy: Neue Strategie. Qt-Signalpfade liefern den Wert als
                plain ``str`` (StrEnum-userData wird von Qt unwrappt).

        Returns:
            ``True`` wenn eine Zeile aktualisiert wurde, ``False`` sonst.

        Raises:
            ValueError: Wenn ``strategy`` kein gueltiger
:class:`PatchStrategy`-Wert ist.
        """
        # Qt-Signalpfade liefern StrEnum-userData als plain str —
        # Value-Lookup normalisiert (idempotent fuer echte Enum-Member).
        return self._repo.update_strategy(winget_id, PatchStrategy(strategy))

    def set_channel_override(
        self, name: str, winget_id: str | None, channel: str
    ) -> bool:
        """Setzt den User-Channel-Override einer App.

        Zwei Ebenen (Application-Fassade fuers GUI, Hexagonal-Contract gewahrt):

        1. **Dauerhaft** in:class:`core.patch_policy.PolicyDB` (per Software-Label,
           normalisiert) — jeder Vollscan re-resolved den Kanal daraus, der
           Override ueberlebt also Re-Scans.
        2. **Sofort** in der persistierten Inventar-Zeile (``update_channel`` per
           ``winget_id``), damit ``load_from_db`` die neu abgeleitete Empfehlung
           ohne Vollscan zeigt — eine zuvor ``notify_only``-App wird so direkt
           upgradebar.

        Args:
            name: Anzeigename der App (Override-Schluessel, wird normalisiert).
            winget_id: Inventar-Zeile fuer das Sofort-Update; ``None`` (kein
                winget-Paket) -> nur der dauerhafte Override wird gesetzt.
            channel: Einer aus:data:`core.patch_policy.USER_OVERRIDE_CHANNELS`.

        Returns:
            ``True`` wenn die Inventar-Zeile aktualisiert wurde (oder kein
            winget_id zu aktualisieren war), ``False`` wenn die Zeile fehlte.

        Raises:
            ValidationError: Bei ungueltigem Kanal (aus ``set_user_override``).
        """
        self._resolver.policy.set_user_override(
            name, channel, reason="GUI-Channel-Auswahl (T-443)"
        )
        if winget_id:
            return self._repo.update_channel(winget_id, channel, "user")
        return True

    def get_default_channel(self) -> str:
        """Globaler Default-Kanal fuer unbekannte Software, Einstellungen)."""
        return self._resolver.policy.get_default_channel()

    def set_default_channel(self, channel: str) -> None:
        """Setzt den globalen Default-Kanal fuer unbekannte Software."""
        self._resolver.policy.set_default_channel(channel)

    # ------------------------------------------------------------------
    # UI-Pfad — Custom-Sources, Notify-Only)
    # ------------------------------------------------------------------

    def add_custom_source(
        self,
        *,
        name: str,
        vendor_url: str,
        version_regex: str,
        platform: Platform = DEFAULT_PLATFORM,
        installed_version: str | None = None,
        notes: str | None = None,
    ) -> CustomSource:
        """Legt eine Custom-Source an.

        Single-Tenant-OSS: kein Tier-Gate mehr — Custom-Sources
        sind für jeden frei. Delegiert die Persistenz an das Repository.
        """
        return self._repo.add_custom_source(
            name=name,
            vendor_url=vendor_url,
            version_regex=version_regex,
            platform=platform,
            installed_version=installed_version,
            notes=notes,
        )

    def list_custom_sources(self) -> list[CustomSource]:
        """Alle Custom-Sources (ungated — auch nach Tier-Downgrade lesbar)."""
        return self._repo.list_custom_sources()

    def delete_custom_source(self, source_id: str) -> bool:
        """Loescht eine Custom-Source (ungated — Aufraeumen immer erlaubt)."""
        return self._repo.delete_custom_source(source_id)

    def check_custom_sources(self) -> int:
        """Prueft alle Custom-Sources per HTTP + persistiert die Ergebnisse.

        Laeuft den:class:`CustomSourceChecker` ueber jede Quelle (fetch +
        Regex + Version-Diff) und schreibt available_version / last_checked_at
        / last_error zurueck. Der Checker wirft nie — eine unerreichbare
        Quelle bekommt ``last_error`` und der Lauf macht weiter. Gedacht fuer
        den Daily-Refresh-/Refresh-Worker (Netzwerk-Calls, nicht im UI-Thread).

        Returns:
            Anzahl gepruefter Quellen.
        """
        count = 0
        for source in self._repo.list_custom_sources():
            updated = self._custom_source_checker.check(source)
            self._repo.update_custom_source(updated)
            count += 1
        return count

    # ------------------------------------------------------------------
    # UI-Pfad — load_from_db
    # ------------------------------------------------------------------

    def offene_und_eol_counts(self) -> tuple[int, int]:
        """Cockpit-Kachel-Metrik: (N offene Updates, M EOL-ohne-Patch).

        Klassifiziert die angereicherte ``recommendation`` aus
:meth:`load_from_db`. Fail-soft: ``(0, 0)`` falls die DB beim
        Cockpit-Render nicht lesbar ist.

        Returns:
            ``(offene_updates, eol_ohne_patch)``.
        """
        try:
            results = self.load_from_db()
        except Exception:  # noqa: BLE001 -- Cockpit-Metrik nie blockierend
            return (0, 0)
        offen = sum(
            1
            for r in results
            if r.recommendation in ("update_urgent", "update", "update_available")
        )
        eol = sum(1 for r in results if r.recommendation == "eol_no_patch")
        return (offen, eol)

    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 200
    ) -> list[AffectedCveRow]:
        """Application-Fassade: betroffene CVEs (CPE-genau) fuers Risikobriefing.

        Delegiert an:meth:`PatchInventoryRepository.list_affected_cves` und
        haelt den Hexagonal-Contract (cross-tool-Konsumenten gehen ueber die
        application-Schicht, nicht direkt an ``data``). Speist Tab 1 des
        Risikobriefings ("bestaetigt betroffen").
        """
        return self._repo.list_affected_cves(min_cvss=min_cvss, limit=limit)

    def anzahl_apps_ohne_cpe(self) -> int:
        """Application-Fassade: Apps ohne CPE (Recall-Transparenz)."""
        return self._repo.count_apps_without_cpe()

    def letzter_vollscan(self) -> datetime | None:
        """Zeitpunkt des letzten Vollscans (fuer den Staleness-Hinweis)."""
        return self._repo.get_last_full_scan_at()

    def load_from_db(self) -> list[PatchScanResult]:
        """Rekonstruiert die ``PatchScanResult``-Liste aus DB-Persistenz.

        Kein Subprocess, kein Netzwerk-Call. Wird vom Patch-Monitor
        beim Tool-Open aufgerufen — User sieht den letzten bekannten
        Stand sofort, der naechste Scan-Button (manuell / daily) ist
        ein zusaetzlicher Aufwand.

        Pipeline:
            1. ``list_inventory`` + ``list_available_versions`` als Dict
               zusammenfuehren.
            2. Pro Inventory-Eintrag: passende CVEs aus ``cve_matches``
               holen, ``recommendation`` rekonstruieren ueber dieselbe
               ``_recommend``-Funktion die PatchService.scan benutzt.
            3.: Recommendation-Engine-Enrichment —
               EOL-Status pro Result aufloesen, passende CSAF-Advisories
               sammeln (falls ``advisory_repository`` injiziert), Engine
               anwenden. Ergebnis: angereicherte Recommendation +
               action_text + recommendation_source.

        Returns:
            ``list[PatchScanResult]``, sortiert nach Name (gleich wie
            ``inventory_snapshot``-Default), ggf. enriched durch die
            Recommendation-Engine.
        """
        inventory = self._repo.list_inventory()
        availables = {av.winget_id: av for av in self._repo.list_available_versions()}

        # Advisory-Lookup einmalig laden, falls Repository injiziert
        # wurde. Wir indexieren nach ``matched_component`` (lowercase) damit
        # der Pro-Result-Lookup O(1) statt O(N) wird.
        advisory_index = self._build_advisory_index()

        results: list[PatchScanResult] = []
        for entry in inventory:
            avail = availables.get(entry.winget_id)
            cves_db = (
                self._repo.list_cve_matches_for_cpe(entry.cpe_string)
                if entry.cpe_string
                else []
            )
            base_result = _build_result_from_db(entry, avail, cves_db)
            enriched = self._enrich_result(base_result, advisory_index)
            results.append(enriched)
        # Custom-Sources als notify_only-Zeilen anhaengen (kein
        # winget_id → keine Checkbox/Strategie, kein CVE-Matching).
        results.extend(
            _custom_source_to_result(s) for s in self._repo.list_custom_sources()
        )
        return results

    def _build_advisory_index(self) -> dict[str, list]:
        """Indexiert offene CSAF-Matches nach ``matched_component`` (lower).

        Returns leer-dict wenn kein Advisory-Repository injiziert wurde —
        Engine laeuft dann ohne CSAF-Anreicherung (EOL kann trotzdem
        triggern).
        """
        if self._advisory_repository is None:
            return {}
        try:
            matches = self._advisory_repository.list_matches()
        except Exception as exc:  # noqa: BLE001 — Repo-Fehler darf load_from_db nicht crashen
            log.warning(
                "Advisory-Repository.list_matches fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return {}
        index: dict[str, list] = {}
        for m in matches:
            key = (m.matched_component or "").lower().strip()
            if not key:
                continue
            index.setdefault(key, []).append(m)
        return index

    def _enrich_result(
        self,
        result: PatchScanResult,
        advisory_index: dict[str, list],
    ) -> PatchScanResult:
        """Wendet die Recommendation-Engine auf ein einzelnes Result an.

        Defensive — bei Resolver-/Engine-Fehler bleibt das Result
        unveraendert (Engine ist optional, kein Crash-Pfad).
        """
        try:
            eol_status = self._eol_resolver.resolve(
                vendor=result.vendor,
                product=result.normalized_name,
                version=result.installed_version,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "EOL-Resolver fuer %s fehlgeschlagen: %s",
                result.name,
                type(exc).__name__,
            )
            eol_status = None

        key = (result.name or "").lower().strip()
        advisories = advisory_index.get(key, [])
        try:
            return apply_recommendation_engine(
                result,
                advisories=advisories,
                eol_status=eol_status,
                title_resolver=self._title_resolver(),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Recommendation-Engine fuer %s fehlgeschlagen: %s — "
                "Basis-Recommendation bleibt.",
                result.name,
                type(exc).__name__,
            )
            return result

    def _title_resolver(self) -> _AdvisoryTitleAdapter | None:
        """Erstellt einen Title-Resolver-Adapter um das Advisory-Repo.

        Wenn kein Repo injiziert ist, gibt's keinen Resolver — Engine
        nutzt dann die ``advisory_id`` als Fallback im Action-Text.
        """
        if self._advisory_repository is None:
            return None
        return _AdvisoryTitleAdapter(self._advisory_repository)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def is_inventory_empty(self) -> bool:
        """``True`` wenn noch nie ein Vollscan lief. UI fragt das beim
        Tool-Open ab um einen "Erst-Inventar"-Hinweis einzublenden."""
        return self._repo.count_inventory() == 0

    def get_last_full_scan_at(self) -> datetime | None:
        """Convenience: leitet:meth:`PatchInventoryRepository.get_last_full_scan_at`
        durch, damit der UI-Code nur den Service kennt."""
        return self._repo.get_last_full_scan_at()

    def get_last_daily_refresh_at(self) -> datetime | None:
        """Convenience: analog last_full_scan_at."""
        return self._repo.get_last_daily_refresh_at()


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


_DEFAULT_LAST_SEEN_FALLBACK: Final[datetime] = datetime(1970, 1, 1, tzinfo=UTC)


def _result_to_inventory_entry(
    result: PatchScanResult, *, full_scan_at: datetime
) -> InventoryEntry:
    """Map ``PatchScanResult`` → ``InventoryEntry`` fuer den Vollscan-
    Persistenz-Pfad. ``result.winget_id`` darf nicht None sein
    (Caller filtert das vor)."""
    assert result.winget_id is not None  # noqa: S101 — Caller-Invariante
    return InventoryEntry(
        winget_id=result.winget_id,
        name=result.name,
        normalized_name=result.normalized_name,
        vendor=result.vendor,
        source=result.source,
        installed_version=result.installed_version,
        cpe_string=_cpe_from_result(result),
        channel=result.channel,
        policy_source=result.policy_source,
        confidence_score=result.confidence_score,
        last_seen_at=full_scan_at,
        last_full_scan_at=full_scan_at,
    )


def _cpe_from_result(result: PatchScanResult) -> str | None:
    """PatchScanResult speichert kein CPE direkt (das wird in der
    Pipeline aus dem ChannelResolver abgeleitet und nur fuer den CVE-
    Matcher genutzt). Wir leiten es aus ``vendor`` + ``installed_version``
    ab — best-effort, ausreichend fuer die Cache-Tabelle.

    Returns:
        CPE-String oder ``None`` wenn kein Vendor bekannt.
    """
    if not result.vendor:
        return None
    # Format laut NVD CPE 2.3 Spec: cpe:2.3:a:<vendor>:<product>:<version>:...
    # Wir nutzen den normalisierten Namen als Product-Approximation.
    product = (
        result.normalized_name.split()[-1] if result.normalized_name else "unknown"
    )
    return (
        f"cpe:2.3:a:{result.vendor}:{product}:{result.installed_version}"
        f":*:*:*:*:windows:*:*"
    )


def _build_result_from_db(
    entry: InventoryEntry,
    available: AvailableVersionEntry | None,
    cves: list,
) -> PatchScanResult:
    """Rekonstruiert ``PatchScanResult`` aus persistierten DB-Eintraegen.

    Verwendet dieselbe:func:`core.patch_result._recommend`-Logik wie der
    Live-Scan, damit DB- und Live-Pfad denselben ``recommendation``-Wert
    liefern (Konsistenz nach-Fix).
    """
    # Build SoftwareItem-aequivalent fuer _recommend-Aufruf
    cve_ids = tuple(c.cve_id for c in cves)
    cvss_max = max(
        (c.cvss_score for c in cves if c.cvss_score is not None), default=None
    )
    exploit = any(c.exploit_available for c in cves)
    eol = any(c.eol for c in cves)
    is_update = available.is_update_available if available else False
    available_version = available.available_version if available else None

    # _recommend braucht eine ChannelDecision mit decision.item.is_update_available.
    # Wir bauen einen Mini-Proxy statt einer echten ChannelDecision.
    from core.patch_channel_resolver import ChannelDecision  # noqa: PLC0415

    item = SoftwareItem(
        name=entry.name,
        version=entry.installed_version,
        winget_id=entry.winget_id,
        source=entry.source,  # type: ignore[arg-type]
        is_update_available=is_update,
        latest_available=available_version,
    )
    decision = ChannelDecision(
        item=item,
        channel=entry.channel,
        policy_source=entry.policy_source,  # type: ignore[arg-type]
        confidence=entry.confidence_score,
        normalized_name=entry.normalized_name,
        cpe=entry.cpe_string,
        reason="loaded-from-db",
    )

    # persistierte User-Strategie fliesst in die Empfehlung —
    # NONE liefert "skipped_by_user", LATEST/STABLE aendern hier nichts
    # an der Klasse (nur am spaeteren Upgrade-Command).
    recommendation = _recommend(
        decision,
        cvss_max,
        exploit,
        available_version,
        strategy=entry.patch_strategy,
    )

    return PatchScanResult(
        name=entry.name,
        normalized_name=entry.normalized_name,
        vendor=entry.vendor or _extract_vendor(entry.cpe_string),
        winget_id=entry.winget_id,
        source=entry.source,  # type: ignore[arg-type]
        installed_version=entry.installed_version,
        available_version=available_version,
        channel=entry.channel,
        policy_source=entry.policy_source,  # type: ignore[arg-type]
        cve_ids=cve_ids,
        cvss_max=cvss_max,
        exploit_available=exploit,
        eol=eol,
        confidence_score=entry.confidence_score,
        recommendation=recommendation,
        patch_strategy=entry.patch_strategy,
        is_update_available=is_update,
    )


def _custom_source_to_result(source: CustomSource) -> PatchScanResult:
    """Bildet eine:class:`CustomSource` auf eine notify_only-Zeile ab.

    Custom-Sources sind Notify-Only: ``winget_id=None`` (→ keine Checkbox,
    kein Strategie-Dropdown), kein CVE-Matching. Der Vendor-Link + der
    aktuelle Status (Update / aktuell / Fehler) stehen im ``action_text``
    (Tooltip + Detail-Panel).
    """
    has_update = is_update_available(source)
    if source.last_error:
        status = source.last_error
    elif has_update:
        status = f"Update verfuegbar: {source.available_version}"
    elif source.available_version:
        status = "aktuell"
    else:
        status = "noch nicht geprueft"
    action_text = f"Eigene Quelle: {source.vendor_url} — {status}"
    return PatchScanResult(
        name=source.name,
        normalized_name=source.name.lower(),
        vendor=None,
        winget_id=None,
        source="custom",
        installed_version=source.installed_version or "unbekannt",
        available_version=source.available_version,
        channel="notify_only",
        policy_source="user",
        cve_ids=(),
        cvss_max=None,
        exploit_available=False,
        eol=False,
        confidence_score=1.0,
        recommendation="notify_only",
        action_text=action_text,
        is_update_available=has_update,
    )


__all__ = [
    "DailyRefreshSummary",
    "FullScanSummary",
    "PatchInventoryService",
]
