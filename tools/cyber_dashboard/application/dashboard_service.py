"""
dashboard_service — Use Cases für das Cyberrisiko-Dashboard.

Orchestriert RSS-Service und Cache-Repository: prüft ob der Cache
frisch ist und lädt entweder aus dem Cache oder von den Live-Feeds.

Sicherheitsdesign:
  - Feed-Inhalte werden nicht geloggt (Datenschutz)
  - Nur Metadaten (Anzahl Meldungen, Quelle) im Log

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from core.feed_settings import external_fetches_allowed
from core.logger import get_logger
from tools.cyber_dashboard.application.csaf_to_cve_adapter import (
    csaf_advisories_to_cves,
)
from tools.cyber_dashboard.application.nvd_service import NvdService
from tools.cyber_dashboard.application.rss_service import RssService
from tools.cyber_dashboard.application.techstack_sync_service import (
    TechStackSyncService,
)
from tools.cyber_dashboard.data.cisa_kev_client import CisaKevClient
from tools.cyber_dashboard.domain.interfaces import (
    ICacheRepository,
    ITechStackRepository,
)
from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    CyberMeldung,
    Kategorie,
    QuelleTyp,
    Schweregrad,
    TechStackEintrag,
    TechStackKandidat,
    YouTubeVideo,
    quellen_fuer_kategorien,
)

log = get_logger(__name__)

# Pool-Vergroesserung beim Stack-Filter: lade_cves liefert maximal so viele
# Zeilen aus der DB, der Stack-Match schneidet sie auf das User-``limit``
# zurueck. Hoeher als 200 lohnt sich nicht — CISA KEV hat nur ~80 aktuelle
# Eintraege, NVD-CRITICAL der letzten 7 Tage typischerweise < 30.
_STACK_POOL_LIMIT = 200
# Defensive Schranken gegen einen manipulierten Tech-Stack-File
# (~/.finlai/techstack.json kann vom User editiert werden — wenn dort
# 10 000 Eintraege oder 100-KB-Strings landen, soll der GUI-Thread nicht
# einfrieren). Vgl. Security-Review.
_MAX_STACK_NAMES = 200
_MAX_STACK_NAME_LEN = 128


def create_default_dashboard_service() -> DashboardService:
    """Default-Factory mit den production-tauglichen Adaptern.

 (RUN2-GUI): Erlaubt den Cross-Tool-GUIs (csaf_advisor,
    techstack), den Service zu beziehen ohne ``data/`` direkt zu
    importieren.

 follow-up: Auch der ``AdvisoryService`` (CSAF) wird lazy
    injiziert — sein Cache speist den CVE-Tab mit echten CVSS-Scores
    und EU-Hersteller-Bezug.

    Returns:
        Vollstaendig verdrahteter ``DashboardService`` (RSS-, NVD-,
        CISA-KEV-Adapter + Tech-Stack- und Cache-Repository + optional
        CSAF-AdvisoryService).
    """
    from tools.cyber_dashboard.data.cache_repository import (  # noqa: PLC0415
        CacheRepository,
    )
    from tools.cyber_dashboard.data.techstack_repository import (  # noqa: PLC0415
        TechStackRepository,
    )

    return DashboardService(
        rss=RssService(),
        cache=CacheRepository(),
        nvd=NvdService(),
        techstack=TechStackRepository(),
        kev_client=CisaKevClient(),
        advisory_service=_try_create_advisory_service(),
        techstack_sync=TechStackSyncService(),
    )


def _try_create_advisory_service():  # noqa: ANN202
    """Baut den CSAF-AdvisoryService defensiv — ``None`` bei Fehler.

    Nutzt die ``csaf_advisor``-eigene Factory
:func:`create_default_advisory_service` als sauberen Cross-Tool-
    Einstiegspunkt — kein direkter ``data/``-Import aus dem
    cyber_dashboard. Wenn das CSAF-Tool nicht installiert ist (z.B.
    Stripped-Lizenz-Tier), die DB nicht initialisiert ist, oder die
    Factory einen anderen Fehler wirft, läuft das Dashboard ohne CSAF
    weiter — CVE-Tab zeigt dann nur KEV/NVD.
    """
    try:
        from tools.csaf_advisor.application.advisory_service import (  # noqa: PLC0415
            create_default_advisory_service,
        )

        return create_default_advisory_service()
    except Exception as exc:  # noqa: BLE001 -- Cross-Tool: jede Init-Variante darf hier scheitern
        log.debug(
            "AdvisoryService-Init fehlgeschlagen (CSAF-Tool inaktiv?): %s",
            type(exc).__name__,
        )
        return None


class DashboardService:
    """Use-Case-Service für das Cyberrisiko-Dashboard.

    Koordiniert RSS-Abruf und lokalen Cache. Bei frischem Cache
    werden keine Netzwerkanfragen durchgeführt.

    Args:
        rss: RSS-Service-Instanz.
        cache: Cache-Repository-Implementierung.
    """

    def __init__(
        self,
        rss: RssService,
        cache: ICacheRepository,
        nvd: NvdService | None = None,
        techstack: ITechStackRepository | None = None,
        kev_client: CisaKevClient | None = None,
        advisory_service: object | None = None,
        techstack_sync: TechStackSyncService | None = None,
    ) -> None:
        self._rss = rss
        self._cache = cache
        self._nvd = nvd
        self._techstack = techstack
        self._kev_client = kev_client
        # follow-up: optional injizierter CSAF-AdvisoryService.
        # ``object`` als Typ-Annotation vermeidet einen harten Import
        # aus ``tools.csaf_advisor`` — der Service nutzt nur
        # ``list_advisories``, das per Duck-Typing aufgelöst wird.
        self._advisory_service = advisory_service
        # optionaler Sync-Service (System-Scan + Patch-Monitor →
        # Tech-Stack-Kandidaten + CPE-basierte CVE-Auflösung).
        self._techstack_sync = techstack_sync

    def lade_meldungen(
        self,
        schweregrad: Schweregrad | None = None,
        quelle: QuelleTyp | None = None,
        erzwingen: bool = False,
        nur_cache: bool = False,
    ) -> list[CyberMeldung]:
        """Lädt Cyber-Meldungen — aus Cache oder von Live-Feeds.

        Args:
            schweregrad: Optionaler Filter nach Schweregrad.
            quelle: Optionaler Filter nach Quelle.
            erzwingen: True = Cache ignorieren, Feeds neu laden.
            nur_cache: True = nur Cache lesen, niemals Live-Feeds laden
                       (verhindert blockierendes Netzwerk im GUI-Thread).

        Returns:
            Meldungen, neueste zuerst.
        """
        cache_frisch = self._cache.ist_frisch()
        # Offline-Modus (externe Abrufe aus) -> nur Cache, kein Netz.
        if not nur_cache and (erzwingen or not cache_frisch) and external_fetches_allowed():
            log.debug(
                "Lade Meldungen von Live-Feeds (cache_frisch=%s, erzwingen=%s)",
                cache_frisch,
                erzwingen,
            )
            t0 = time.monotonic()
            meldungen = self._rss.lade_meldungen()
            log.info(
                "Live-Feeds geladen in %.1fs: %d Meldungen",
                time.monotonic() - t0,
                len(meldungen),
            )
            try:
                self._cache.speichere_meldungen(meldungen)
            except (OSError, RuntimeError) as exc:
                log.warning("Cache-Speicherung fehlgeschlagen: %s", type(exc).__name__)
        else:
            log.debug("Meldungen aus Cache (frisch)")

        return self._cache.lade_meldungen(
            schweregrad=schweregrad,
            quelle=quelle,
        )

    def lade_videos(
        self,
        erzwingen: bool = False,
        max_videos: int = 10,
        nur_cache: bool = False,
    ) -> list[YouTubeVideo]:
        """Lädt YouTube-Videos — aus Cache oder von YouTube RSS.

        Args:
            erzwingen: True = Cache ignorieren, Feed neu laden.
            max_videos: Maximale Anzahl Videos.
            nur_cache: True = nur Cache lesen, niemals Live-Feed laden.

        Returns:
            Videos, neueste zuerst.
        """
        if (
            not nur_cache
            and (erzwingen or not self._cache.ist_frisch())
            and external_fetches_allowed()
        ):
            log.debug("Lade YouTube-Videos von RSS")
            videos = self._rss.lade_youtube_videos(max_videos=max_videos)
            try:
                self._cache.speichere_videos(videos)
            except (OSError, RuntimeError) as exc:
                log.warning(
                    "Video-Cache-Speicherung fehlgeschlagen: %s",
                    type(exc).__name__,
                )

        return self._cache.lade_videos(limit=max_videos)

    @property
    def nvd_service(self) -> NvdService | None:
        """Gibt die interne NvdService-Instanz zurück.

        Wird von der Einstellungs-UI benötigt um denselben NvdService
        zu teilen (Dependency Injection statt doppelter Instanziierung).

        Returns:
            NvdService-Instanz oder None.
        """
        return self._nvd

    def nvd_aktiv(self) -> bool:
        """True wenn NVD-Integration aktiv und API-Key vorhanden ist.

        Returns:
            True wenn NVD-Abfragen möglich sind.
        """
        return self._nvd is not None and self._nvd.api_key_gesetzt()

    def nvd_status_hint(self) -> str | None:
        """Liefert einen User-facing Hinweis zum letzten NVD-Aufruf.

        Returns:
            Lokalisierter Hinweis-String fuer Banner/Status-Label, oder
            ``None`` wenn kein Hinweis noetig ist (Online + API-Key OK).
        """
        if self._nvd is None:
            return None
        if not self._nvd.api_key_gesetzt():
            return "kein NVD API-Key gesetzt — Einstellungen > Cyber-Dashboard"
        from tools.cyber_dashboard.application.nvd_service import (  # noqa: PLC0415
            NvdStatus,
        )

        status = self._nvd.last_status
        if status == NvdStatus.RATE_LIMIT:
            return "NVD-Rate-Limit erreicht — bitte spaeter erneut versuchen"
        if status == NvdStatus.OFFLINE_NO_CACHE:
            return "NVD nicht erreichbar — kein Cache vorhanden"
        if status == NvdStatus.SERVER_ERROR:
            # NVD-503: transienter Server-Ausfall, Cache wird angezeigt. Der
            # Cache ist NICHT veraltet — daher bewusst nicht "Cache veraltet",
            # sondern der präzise Hinweis mit dem Stand-Datum des Cache.
            return (
                f"NVD gerade nicht erreichbar — Anzeige aus Cache vom "
                f"{self._format_fetched_at(self._nvd.last_fetched_at)}"
            )
        if status == NvdStatus.CACHE_STALE_OFFLINE:
            return "NVD offline — Cache veraltet"
        return None

    @staticmethod
    def _format_fetched_at(fetched_at: datetime | None) -> str:
        """Formatiert den Cache-Stand-Zeitpunkt für einen User-Hinweis.

        Args:
            fetched_at: Zeitpunkt des zugrunde liegenden Cache-Fetch (UTC)
                oder ``None``, wenn kein Zeitpunkt bekannt ist.

        Returns:
            Datum/Uhrzeit als ``TT.MM.JJJJ HH:MM``-String, oder ``"unbekannt"``
            wenn kein Zeitpunkt vorliegt.
        """
        if fetched_at is None:
            return "unbekannt"
        return fetched_at.strftime("%d.%m.%Y %H:%M")

    def lade_cves(self, erzwingen: bool = False) -> None:
        """Laedt CVEs von KEV / NVD / CSAF in den lokalen Cache.

        Drei Quellen, alle defensiv — Fehler einer Quelle blockiert
        die anderen nicht:

          1. **CISA KEV** (immer) — aktiv ausgenutzte Schwachstellen,
             pauschal als HIGH/9.0 klassifiziert (kein CVSS im Feed).
          2. **NVD** (optional, API-Key) — neueste CRITICAL der letzten
             7 Tage + 10 zusätzliche KEV-CVEs mit echten CVSS-Scores.
          3. **CSAF-Advisories** (optional follow-up) — BSI WID
             und Hersteller-Advisories aus dem ``csaf_advisor``-Tool.
             Bringen echte CRITICAL/HIGH/MEDIUM/LOW-Severities und
             EU-Hersteller-Bezug (SEPPmail, SAP, Siemens,...).

        Args:
            erzwingen: Aktuell ungenutzt — CVEs werden immer neu geladen.
        """
        if not external_fetches_allowed():
            log.debug("CVE-Abruf uebersprungen: Offline-Modus (externe Abrufe aus).")
            return
        # 1. CSAF-Advisories zuerst — sie liefern echte CVSS-Scores.
        # Reihenfolge ist wichtig: KEV-INSERT-OR-REPLACE soll danach
        # ``cisa_kev=True`` auf eventuelle Cross-Source-Duplikate
        # zurückschreiben (vgl. Korrektheits-Review P1).
        self._lade_csaf_cves()

        # 2. CISA KEV — überschreibt ggf. CSAF-Einträge mit demselben
        # CVE-ID und stellt damit den ``cisa_kev=True``-Marker wieder
        # her. KEV-Severity bleibt HIGH/9.0 (Feed-Limitation), aber das
        # ist die autoritativere Klassifizierung für aktiv ausgenutzte
        # CVEs als der theoretische CSAF-Score.
        if self._kev_client is not None:
            try:
                kev_eintraege = self._kev_client.fetch_recent_kevs()
                if kev_eintraege:
                    self._cache.speichere_cves(kev_eintraege)
            except (OSError, RuntimeError, ValueError, ConnectionError) as exc:
                log.warning("KEV-Laden fehlgeschlagen: %s", type(exc).__name__)

        # 2. NVD optional: liefert CVSS-Scores fuer neueste kritische CVEs
        if not self.nvd_aktiv():
            return
        try:
            t0 = time.monotonic()
            cves_kritisch = self._nvd.lade_neueste_cves(  # type: ignore[union-attr]
                tage=7,
                schweregrad="CRITICAL",
                max_results=20,
            )
            cves_kev = self._nvd.lade_kev_cves(max_results=10)  # type: ignore[union-attr]
            self._cache.speichere_cves(cves_kritisch + cves_kev)
            log.info(
                "NVD: %d CVEs geladen in %.1fs",
                len(cves_kritisch) + len(cves_kev),
                time.monotonic() - t0,
            )
        except (OSError, RuntimeError, ValueError, ConnectionError) as exc:
            log.warning("NVD CVE-Laden fehlgeschlagen: %s", type(exc).__name__)

    def _lade_csaf_cves(self) -> None:
        """Liest CSAF-Advisories aus dem ``csaf_advisor``-Repository und
        speichert sie als ``CveEintrag`` im cyber_dashboard-Cache.

        Defensiv: Wenn ``advisory_service`` ``None`` ist (Tool nicht
        installiert / Init fehlgeschlagen) oder das ``list_advisories``-
        Interface nicht passt (Duck-Typing-Fehler), wird stumm
        übersprungen — KEV und NVD bleiben funktionsfähig.

 follow-up.
        """
        if self._advisory_service is None:
            return
        try:
            advisories = self._advisory_service.list_advisories(days=90)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 -- Cross-Tool-Read, defensive
            log.warning(
                "CSAF-Lade fehlgeschlagen (list_advisories): %s",
                type(exc).__name__,
            )
            return

        if not advisories:
            log.debug("CSAF: keine Advisories im Repository (Tab noch nie geöffnet?)")
            return

        try:
            csaf_cves = csaf_advisories_to_cves(advisories)
            if csaf_cves:
                self._cache.speichere_cves(csaf_cves)
                log.info(
                    "CSAF: %d Advisories als CVE-Eintraege in den Cache (%d Rohzeilen)",
                    len(csaf_cves),
                    len(advisories),
                )
        except (OSError, RuntimeError, ValueError) as exc:
            log.warning(
                "CSAF-Konvertierung fehlgeschlagen: %s",
                type(exc).__name__,
            )

    def zaehle_statistiken(self) -> dict[str, int]:
        """Gibt CVE-Zähler nach Schweregrad zurück.

        Returns:
            Dict mit Schweregrad-Counts und KEV-Count.
        """
        try:
            return self._cache.zaehle_cves_nach_schweregrad()
        except (OSError, RuntimeError) as exc:
            log.warning("Statistiken fehlgeschlagen: %s", type(exc).__name__)
            return {}

    def lade_cves_gefiltert(
        self,
        schweregrad: str | None = None,
        nur_kev: bool = False,
        nur_stack: bool = False,
        limit: int = 50,
    ) -> list[CveEintrag]:
        """Lädt CVEs aus dem Cache mit optionalen Filtern.

        Args:
            schweregrad: Optionaler Filter (CRITICAL/HIGH/MEDIUM/LOW).
            nur_kev: True = nur CISA KEV CVEs.
            nur_stack: True = nur CVEs deren ``betroffene_produkte`` mit
                einem aktiven Tech-Stack-Eintrag (Substring, case-insensitive)
                matchen. Hebt das ``limit`` für die DB-Abfrage temporär auf
                200 an, damit der Stack-Filter aus einem größeren Pool
                schöpfen kann; das Endergebnis bleibt auf ``limit``
                beschränkt.
            limit: Maximale Anzahl im Ergebnis.

        Returns:
            Gefilterte CVE-Einträge, neueste zuerst.
        """
        try:
            cves = self._cache.lade_cves(
                schweregrad=schweregrad,
                nur_kev=nur_kev,
                limit=_STACK_POOL_LIMIT if nur_stack else limit,
            )
        except (OSError, RuntimeError) as exc:
            log.warning("CVE-Filter-Laden fehlgeschlagen: %s", type(exc).__name__)
            return []

        if nur_stack:
            cves = self._filtere_nach_stack(cves)[:limit]

        return cves

    def _filtere_nach_stack(
        self, cves: list[CveEintrag]
    ) -> list[CveEintrag]:
        """Filtert CVEs auf solche die mit dem aktiven Tech-Stack matchen.

        Match-Regel: case-insensitive Substring-Suche jedes aktiven
        Stack-``name`` gegen jeden CVE-``betroffene_produkte``-Eintrag.

        Defensive Schranken: max. ``_MAX_STACK_NAMES`` Namen,
        ``_MAX_STACK_NAME_LEN`` Zeichen pro Name — Schutz gegen
        manipulierte Tech-Stack-Datei (vgl. Security-Review).

        Args:
            cves: Eingangsliste der CVEs.

        Returns:
            Untermenge die mindestens einen Stack-Match hat. Leer wenn
            kein TechStack-Repository injiziert ist, der Stack leer
            ist, oder das Laden des Stacks scheitert.
        """
        if self._techstack is None:
            return []
        try:
            stack = self._techstack.lade()
        except (OSError, RuntimeError, ValueError) as exc:
            log.warning(
                "Stack-Filter: TechStack-Laden fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []
        aktive_namen = [
            e.name[:_MAX_STACK_NAME_LEN].lower()
            for e in stack
            if e.aktiv and e.name
        ][:_MAX_STACK_NAMES]
        if not aktive_namen:
            return []
        return [
            c
            for c in cves
            if any(
                produkt and name in produkt.lower()
                for produkt in c.betroffene_produkte
                for name in aktive_namen
            )
        ]

    def suche_cves_produkt(
        self,
        produkt: str,
        tage: int = 30,
    ) -> list[CveEintrag]:
        """Sucht CVEs für ein Produkt via NVD API.

        Args:
            produkt: Produktname (z.B. "Windows", "Python").
            tage: Zeitraum in Tagen.

        Returns:
            Gefundene CVEs oder leere Liste wenn NVD inaktiv.
        """
        if not self.nvd_aktiv():
            return []
        try:
            return self._nvd.suche_produkt(produkt=produkt, tage=tage)  # type: ignore[union-attr]
        except (OSError, RuntimeError, ValueError, ConnectionError) as exc:
            log.warning("Produkt-Suche fehlgeschlagen: %s", type(exc).__name__)
            return []

    # ------------------------------------------------------------------
    # Tech-Stack
    # ------------------------------------------------------------------

    def lade_techstack(self) -> list[TechStackEintrag]:
        """Lädt den persönlichen Tech-Stack.

        Returns:
            Liste der Tech-Stack-Einträge oder leere Liste.
        """
        if self._techstack is None:
            return []
        return self._techstack.lade()

    def get_at_starter_stack(self) -> list[TechStackEintrag]:
        """Liefert die AT-Steuerkanzlei-Vorschlagsliste (Opt-in-Default).

 (RUN2-GUI): Gibt der GUI Zugriff auf
        ``AT_STARTER_STACK`` ohne dass das Widget die Konstante direkt
        aus dem Repository importieren muss.

        Returns:
            Liste der Default-Eintraege (Windows, Office, BMD,...).
        """
        from tools.cyber_dashboard.data.techstack_repository import (  # noqa: PLC0415
            AT_STARTER_STACK,
        )

        return list(AT_STARTER_STACK)

    def techstack_hinzufuegen(self, eintrag: TechStackEintrag) -> None:
        """Fügt einen Eintrag zum Tech-Stack hinzu.

        Args:
            eintrag: Neuer Tech-Stack-Eintrag.
        """
        if self._techstack is not None:
            self._techstack.hinzufuegen(eintrag)

    def techstack_entfernen(self, name: str) -> None:
        """Entfernt einen Eintrag aus dem Tech-Stack.

        Args:
            name: Name des zu entfernenden Produkts.
        """
        if self._techstack is not None:
            self._techstack.entfernen(name)

    def techstack_sync_kandidaten(self) -> list[TechStackKandidat]:
        """Ermittelt Übernahme-Vorschläge aus System-Scan + Patch-Monitor.

        Liefert nur Produkte, die noch NICHT im Tech-Stack stehen (Dedup
        gegen den Bestand per case-insensitivem Namen). Fail-soft: leere
        Liste, wenn kein Sync-Service verdrahtet ist.

        Returns:
            Neue, nach Name sortierte Kandidaten für den Vorschau-Dialog.
        """
        if self._techstack_sync is None:
            return []
        bestehende = {e.name.strip().lower() for e in self.lade_techstack()}
        return [
            k
            for k in self._techstack_sync.ermittle_kandidaten()
            if k.eintrag.name.strip().lower() not in bestehende
        ]

    def techstack_uebernehmen(self, eintraege: list[TechStackEintrag]) -> int:
        """Übernimmt die ausgewählten Sync-Einträge in den Tech-Stack.

        Lädt den Bestand einmal, hängt die neuen (nach Name deduplizierten)
        Einträge an und speichert einmal — ein Schreibvorgang statt N.

        Args:
            eintraege: Vom User im Vorschau-Dialog ausgewählte Einträge.

        Returns:
            Anzahl der tatsächlich neu hinzugefügten Einträge.
        """
        if self._techstack is None or not eintraege:
            return 0
        stack = self._techstack.lade()
        namen = {e.name.strip().lower() for e in stack}
        hinzugefuegt = 0
        for eintrag in eintraege:
            key = eintrag.name.strip().lower()
            if not key or key in namen:
                continue
            stack.append(eintrag)
            namen.add(key)
            hinzugefuegt += 1
        if hinzugefuegt:
            self._techstack.speichere(stack)
        return hinzugefuegt

    # ------------------------------------------------------------------
    # Phishing-Inbox (2026-05-28 Phishing-Radar-Refactor)
    # ------------------------------------------------------------------

    _SCHWEREGRAD_RANG: dict[Schweregrad, int] = {  # type: ignore[assignment]
        Schweregrad.INFO: 0,
        Schweregrad.NIEDRIG: 1,
        Schweregrad.MITTEL: 2,
        Schweregrad.HOCH: 3,
        Schweregrad.KRITISCH: 4,
    }

    def lade_phishing_alerts(
        self,
        kategorien: Iterable[Kategorie] = (Kategorie.PHISHING_CONSUMER,),
        min_schweregrad: Schweregrad = Schweregrad.MITTEL,
        seit_stunden: int = 168,
        nur_ungelesen: bool = False,
        nur_cache: bool = True,
        limit: int = 100,
    ) -> list[CyberMeldung]:
        """Liefert Phishing-Alerts gefiltert nach Kategorie/Schweregrad/Zeit.

        Default-Werte sind auf den Modal-Tab "Aktuelle Warnungen"
        zugeschnitten (7 Tage, ≥MITTEL, alle Konsumenten-Quellen).
        Der Mainpage-Banner setzt strengere Werte (24h, ≥HOCH, max=6 AP3).

        Snooze: Items mit aktiver Snooze (``snooze_bis > now``) werden
        immer ausgeblendet.

        Args:
            kategorien: Erlaubte Kategorien (`PHISHING_CONSUMER`,...).
            min_schweregrad: Minimaler Schweregrad inkl.
            seit_stunden: Wie weit zurueck (Stunden).
            nur_ungelesen: True = nur Items ohne ``gelesen_am``.
            nur_cache: True = nicht refreshen (GUI-Thread-sicher).
            limit: Maximale Anzahl im Ergebnis.

        Returns:
            Liste der Meldungen, sortiert nach Schweregrad DESC,
            Datum DESC.
        """
        # Quellen-Filter aus Kategorien ableiten (zentrale Domain-Logik).
        relevante_quellen = quellen_fuer_kategorien(kategorien)
        if not relevante_quellen:
            return []
        if nur_cache:
            meldungen = self._cache.lade_meldungen(limit=max(limit * 5, 500))
        else:
            meldungen = self.lade_meldungen()

        jetzt = datetime.now(UTC)
        cutoff = jetzt - timedelta(hours=seit_stunden)
        min_rang = self._SCHWEREGRAD_RANG.get(min_schweregrad, 2)

        gefiltert: list[CyberMeldung] = [
            m
            for m in meldungen
            if m.quelle in relevante_quellen
            and self._SCHWEREGRAD_RANG.get(m.schweregrad, 0) >= min_rang
            and m.veroeffentlicht >= cutoff
        ]
        if not gefiltert:
            return []

        # State (Read/Snooze) laden — defensive Defaults wenn DB-Fehler.
        try:
            state = self._cache.lade_state_fuer(m.guid for m in gefiltert)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "Phishing-State-Laden fehlgeschlagen: %s", type(exc).__name__
            )
            state = {}

        sichtbar: list[CyberMeldung] = []
        for m in gefiltert:
            gelesen_am, snooze_bis = state.get(m.guid, (None, None))
            if snooze_bis is not None and snooze_bis > jetzt:
                continue
            if nur_ungelesen and gelesen_am is not None:
                continue
            sichtbar.append(m)

        sichtbar.sort(
            key=lambda m: (
                self._SCHWEREGRAD_RANG.get(m.schweregrad, 0),
                m.veroeffentlicht,
            ),
            reverse=True,
        )
        return sichtbar[:limit]

    def markiere_gelesen(self, guids: Iterable[str]) -> None:
        """Markiert Phishing-Alerts als gelesen. Idempotent."""

        try:
            self._cache.markiere_gelesen(guids)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "markiere_gelesen fehlgeschlagen: %s", type(exc).__name__
            )

    def markiere_ungelesen(self, guids: Iterable[str]) -> None:
        """Setzt Gelesen-Status zurueck."""

        try:
            self._cache.markiere_ungelesen(guids)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "markiere_ungelesen fehlgeschlagen: %s", type(exc).__name__
            )

    def schiebe_auf(
        self,
        guid: str,
        bis: datetime,
        quelle: QuelleTyp | None = None,
    ) -> None:
        """Verschiebt eine Meldung in die Zukunft (``bis`` UTC).

        Args:
            guid: GUID der Meldung.
            bis: Snooze-Endzeitpunkt (UTC).
            quelle: Quelle der Meldung. Die GUI haelt die Meldung bereits
                vor und reicht sie durch — dann entfaellt der Cache-Scan.
                Nur wenn ``None`` wird die Quelle aus dem Cache aufgeloest
                (Fallback ``WATCHLIST_AT``).
        """

        try:
            if quelle is None:
                quelle = QuelleTyp.WATCHLIST_AT
                for m in self._cache.lade_meldungen(limit=500):
                    if m.guid == guid:
                        quelle = m.quelle
                        break
            self._cache.schiebe_auf(guid, bis, quelle)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "schiebe_auf fehlgeschlagen: %s", type(exc).__name__
            )

    def read_state_fuer(self, guids: Iterable[str]) -> set[str]:
        """Liefert die Teilmenge der ``guids``, die als gelesen markiert sind.

        Oeffentliche Service-API, damit die GUI den Read-State NICHT ueber
        einen Durchgriff auf das private Repository ermitteln muss
        (Hexagonal-Schichtgrenze gui -> application -> data).

        Args:
            guids: Zu pruefende GUIDs.

        Returns:
            Set der GUIDs mit gesetztem ``gelesen_am``. Leeres Set bei
            DB-Fehler (defensive Default).
        """

        try:
            state = self._cache.lade_state_fuer(guids)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "read_state_fuer fehlgeschlagen: %s", type(exc).__name__
            )
            return set()
        return {
            guid
            for guid, (gelesen_am, _snooze) in state.items()
            if gelesen_am is not None
        }

    def zaehle_ungelesene(self, kategorien: Iterable[Kategorie]) -> int:
        """Zaehlt ungelesene Meldungen in den angegebenen Kategorien."""

        quellen = quellen_fuer_kategorien(kategorien)
        if not quellen:
            return 0
        try:
            return self._cache.zaehle_ungelesene(quellen)
        except (OSError, RuntimeError) as exc:
            log.warning(
                "zaehle_ungelesene fehlgeschlagen: %s", type(exc).__name__
            )
            return 0

    def zaehle_seit(
        self,
        kategorien: Iterable[Kategorie],
        stunden: int,
    ) -> int:
        """Zaehlt Meldungen aus ``kategorien`` der letzten ``stunden``.

        Nutzt einen SQL-COUNT im Repository (kein Laden+Entschluesseln aller
        Cache-Zeilen nur zum Zaehlen).
        """

        quellen = quellen_fuer_kategorien(kategorien)
        if not quellen:
            return 0
        cutoff = datetime.now(UTC) - timedelta(hours=stunden)
        try:
            return self._cache.zaehle_seit(quellen, cutoff)
        except (OSError, RuntimeError) as exc:
            log.warning("zaehle_seit fehlgeschlagen: %s", type(exc).__name__)
            return 0

    def suche_cves_fuer_stack(self, tage: int = 30) -> list[CveEintrag]:
        """Sucht CVEs für alle aktiven Tech-Stack-Einträge.

        Zwei Quellen, dedupliziert über die CVE-ID:

          1. **NVD-Namenssuche** (nur wenn ein NVD-API-Key gesetzt ist) —
             liefert frische CVEs mit echter Beschreibung pro Produktname.
          2. **CPE-Treffer aus dem Patch-Monitor** — die lokal
             bereits gematchten ``cve_matches`` der Stack-CPEs; braucht
             **keinen** NVD-Key und liefert daher Treffer auch ohne Key.

        NVD-Treffer haben Vorrang (bessere Beschreibung); CPE-Treffer
        ergänzen, was die Namenssuche nicht (oder mangels Key gar nicht)
        gefunden hat.

        Args:
            tage: Zeitraum in Tagen für die NVD-Namenssuche.

        Returns:
            Deduplizierte CVE-Liste, nach CVSS-Score absteigend.
        """
        aktive = [e for e in self.lade_techstack() if e.aktiv]
        alle_cves: list[CveEintrag] = []
        gesehen: set[str] = set()

        # 1. NVD-Namenssuche — nur mit API-Key + nur online Offline-Modus);
        # offline bleiben die lokalen CPE-Treffer (Schritt 2) erhalten.
        if self.nvd_aktiv() and external_fetches_allowed():
            for eintrag in aktive:
                try:
                    cves = self._nvd.suche_produkt(eintrag.name, tage)  # type: ignore[union-attr]
                except (OSError, RuntimeError, ValueError, ConnectionError) as exc:
                    log.warning(
                        "Stack-CVE-Suche fehlgeschlagen (%s): %s",
                        eintrag.name,
                        type(exc).__name__,
                    )
                    continue
                for c in cves:
                    if c.cve_id not in gesehen:
                        gesehen.add(c.cve_id)
                        alle_cves.append(c)

        # 2. CPE-basierte Treffer aus dem Patch-Monitor (kein NVD-Key nötig).
        if self._techstack_sync is not None:
            cpe_namen = [(e.cpe, e.name) for e in aktive if e.cpe]
            if cpe_namen:
                for c in self._techstack_sync.cves_fuer_cpes(cpe_namen):
                    if c.cve_id not in gesehen:
                        gesehen.add(c.cve_id)
                        alle_cves.append(c)

        return sorted(alle_cves, key=lambda c: c.cvss_score, reverse=True)

    def lade_cves_briefing_pool(self, limit: int = 40) -> list[CveEintrag]:
        """CVE-Pool fuer das KI-Briefing: generische Top-CVEs + dedizierte
        Tech-Stack-CVEs, dedupliziert ueber die CVE-ID.

        Schliesst die Luecke, dass:meth:`suche_cves_fuer_stack`
        Treffer findet (CPE-Treffer offline + NVD-Namenssuche wenn Key/online),
        die nicht im generischen Top-Pool stehen und das Briefing sonst nie
        sieht. Persistiert NICHTS — der generische Cache und das CVE-Tab bleiben
        unveraendert; nur das Briefing bekommt den angereicherten Pool.

        Args:
            limit: Obergrenze fuer den generischen Anteil.

        Returns:
            Zusammengefuehrte CVE-Liste (generisch zuerst, dann ergaenzende
            Stack-CVEs), dedupliziert ueber die CVE-ID.
        """
        pool = list(self.lade_cves_gefiltert(limit=limit))
        gesehen = {c.cve_id for c in pool}
        for c in self.suche_cves_fuer_stack():
            if c.cve_id not in gesehen:
                gesehen.add(c.cve_id)
                pool.append(c)
        return pool
