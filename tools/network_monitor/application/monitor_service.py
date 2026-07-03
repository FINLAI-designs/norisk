"""monitor_service — Use-Case-Schicht fuer den Netzwerk-Monitor.

Kapselt die ``data/``-Adapter (``blocklist_loader``, ``monitor_exporter``,
``monitor_worker``) hinter einer Service-API, damit das
``NetworkMonitorWidget`` nicht mehr direkt aus ``data/`` importieren muss.

Schichtzugehoerigkeit: ``application/`` (Hexagonal — orchestriert
Domain-/Data-Operationen, kein UI-Code).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from core.logger import get_logger
from tools.network_monitor.application.threat_checker import ThreatChecker
from tools.network_monitor.domain.interfaces import IConnectionRepository

if TYPE_CHECKING:
    # ``NetworkMonitorWorker`` wird hier re-exportiert, damit
    # GUI-Konsumenten den Typ aus der application-Schicht beziehen
    # koennen statt aus ``data/`` (import-linter erlaubt application→data,
    # aber nicht gui→data).
    from tools.network_monitor.application.anomaly_detector import AnomalyService
    from tools.network_monitor.application.conversation_service import (
        ConversationService,
    )
    from tools.network_monitor.application.threat_feed_service import ThreatFeedService
    from tools.network_monitor.application.whitelist_service import WhitelistService
    from tools.network_monitor.data.monitor_worker import NetworkMonitorWorker
    from tools.network_monitor.domain.interfaces import (
        IDnsQueryRepository,
        IProcessTrafficRepository,
    )

__all__ = ["MonitorService", "NetworkMonitorWorker"]

logger = get_logger(__name__)


class MonitorService:
    """Use-Case-Service fuer den Netzwerk-Monitor.

    Kapselt Blocklist-Loader, History-Exporter und Worker-Factory hinter
    einer schmalen API, damit die GUI nicht direkt gegen die ``data/``-
    Schicht arbeitet GUI/data-Trennung).
    """

    @staticmethod
    def create_threat_checker(blocklist_path: Path | None = None) -> ThreatChecker:
        """Baut einen ``ThreatChecker`` aus Blocklist + gecachten Feeds + Whitelist.

        Lokale ``blocklist.txt`` und ``whitelist.txt`` sind immer verfuegbar; der
        verschluesselte Feed-Cache F-D) wird best-effort dazugemischt —
        fehlt ein ``KeyManager`` (z. B. Nicht-Windows/Tests ohne DB), faellt die
        Factory fail-soft auf Blocklist + Whitelist zurueck.

        Args:
            blocklist_path: Optionaler Pfad zur Blocklist-Datei. ``None``
                nutzt die tool-interne ``data/blocklist.txt``.

        Returns:
            ``ThreatChecker``-Instanz mit den zusammengefuehrten Eintraegen.
        """
        from tools.network_monitor.data.blocklist_loader import (  # noqa: PLC0415
            load_blocklist,
            load_whitelist,
        )

        whitelist = load_whitelist()
        try:
            service = MonitorService.create_threat_feed_service(
                blocklist_path=blocklist_path
            )
            return ThreatChecker(entries=service.build_entries(), whitelist=whitelist)
        except Exception as exc:  # noqa: BLE001 — kein KeyManager/keine DB → fail-soft
            logger.info(
                "Feed-Cache nicht verfuegbar (%s) — nur lokale Blocklist.",
                type(exc).__name__,
            )
            return ThreatChecker(
                entries=load_blocklist(blocklist_path), whitelist=whitelist
            )

    @staticmethod
    def create_threat_feed_service(
        blocklist_path: Path | None = None,
    ) -> ThreatFeedService:
        """Baut einen ``ThreatFeedService`` mit den Default-Quellen (Factory, F-D).

        Haelt den ``data/``-Cache-Import in der Application-Schicht. Die
        Konstruktion oeffnet die verschluesselte DB und benoetigt daher einen
        aktiven ``KeyManager`` — der Aufrufer (GUI-Refresh-Worker) ruft die
        Factory erst zur Worker-Startzeit und behandelt ``RuntimeError`` fail-soft.

        Args:
            blocklist_path: Optionaler Pfad zur Blocklist (Tests).

        Returns:
            ``ThreatFeedService`` ueber die abuse.ch-CC0-Quellen.
        """
        from tools.network_monitor.application.threat_feed_service import (  # noqa: PLC0415
            ThreatFeedService,
        )

        return ThreatFeedService(blocklist_path=blocklist_path)

    @staticmethod
    def create_whitelist_service(
        whitelist_path: Path | None = None,
    ) -> WhitelistService:
        """Baut einen DB-freien ``WhitelistService`` für die Whitelist-Pflege (F-D-GUI).

        Anders als:meth:`create_threat_feed_service` öffnet diese Factory **keine**
        verschlüsselte DB — sie arbeitet nur auf der nutzer-editierbaren
        ``whitelist.txt`` und kann daher auch ohne ``KeyManager`` aufgerufen werden
        (Bedrohungslisten-Tab: Ausnahmen anzeigen/hinzufügen/entfernen).

        Args:
            whitelist_path: Optionaler Pfad (Tests). ``None`` nutzt die Profil-Datei.

        Returns:
            ``WhitelistService`` auf der nutzer-editierbaren Whitelist.
        """
        from tools.network_monitor.application.whitelist_service import (  # noqa: PLC0415
            WhitelistService,
        )

        return WhitelistService(whitelist_path=whitelist_path)

    @staticmethod
    def create_conversation_service(
        repository: IConnectionRepository | None = None,
        traffic_repository: IProcessTrafficRepository | None = None,
    ) -> ConversationService:
        """Baut einen ``ConversationService`` über die Verbindungs-Historie (Phase 5).

        Konstruiert das Connection-History-Repository (verschlüsselte DB) und reicht es
        in den Service. Wie die anderen DB-gebundenen Factories kann die Konstruktion
        ohne aktiven ``KeyManager`` einen ``RuntimeError`` werfen — der Konversationen-Tab
        ruft die Factory beim Tab-Aufbau und behandelt diesen Fehler fail-soft (dann
        bleibt der Tab leer, kein Crash).

        Args:
            repository: Optionales, bereits geöffnetes Connection-History-Repo.
                ``None`` konstruiert ein frisches (= öffnet die ``network_monitor``-DB
                erneut). Der eingebettete Live-Tab reicht hier die schon gebauten
                History-Repos durch, damit nicht jeder Sub-Tab dieselbe DB nochmal
                öffnet (Folge aus: zu viele synchrone DB-Öffnungen beim
                Live-Aufbau).
            traffic_repository: Analog für das ProcessTraffic-Repo.

        Returns:
            ``ConversationService`` für den Konversationen-Tab.
        """
        from tools.network_monitor.application.conversation_service import (  # noqa: PLC0415
            ConversationService,
        )
        from tools.network_monitor.data.connection_repository import (  # noqa: PLC0415
            ConnectionHistoryRepository,
        )
        from tools.network_monitor.data.process_traffic_repository import (  # noqa: PLC0415
            ProcessTrafficRepository,
        )

        # Beide Repos teilen DB + KeyManager: konstruiert das eine, konstruiert das
        # andere ebenso. Das Traffic-Repo liefert die optionale ETW-Byte-Anreicherung
        # (ohne elevated Collector schlicht 0 Bytes). Bereits gebaute Repos werden
        # wiederverwendet, statt die DB erneut zu öffnen-Folge).
        return ConversationService(
            repository=repository
            if repository is not None
            else ConnectionHistoryRepository(),
            traffic_repository=traffic_repository
            if traffic_repository is not None
            else ProcessTrafficRepository(),
        )

    @staticmethod
    def export_history(
        repository: IConnectionRepository,
        target_path: Path,
        hours: int = 24,
    ) -> int:
        """Exportiert die Verbindungshistorie als CSV.

        Args:
            repository: Geoeffnetes Connection-History-Repository.
            target_path: Ziel-Pfad der CSV-Datei.
            hours: Zeitfenster in Stunden (Default 24).

        Returns:
            Anzahl exportierter Eintraege.
        """
        from tools.network_monitor.data.monitor_exporter import (  # noqa: PLC0415
            export_history_csv,
        )

        return export_history_csv(repository, target_path, hours=hours)

    @staticmethod
    def create_worker(
        threat_checker: ThreatChecker | None = None,
        include_per_process: bool = False,
        connection_repo: IConnectionRepository | None = None,
    ) -> NetworkMonitorWorker:
        """Erstellt einen ``NetworkMonitorWorker`` (Factory).

        Args:
            threat_checker: Optionaler ``ThreatChecker``; ohne ihn werden
                Verbindungen nicht gegen die Blocklist geprueft.
            include_per_process: Ob Per-Prozess-Stats gesammelt werden
                sollen (Pro-Feature).
            connection_repo: Optionales History-Repository. Gesetzt persistiert
                der Worker den Verbindungs-Snapshot SELBST im Worker-Thread statt im UI-Thread-Slot (der die GUI einfror).

        Returns:
            Frischer Worker, noch nicht gestartet.
        """
        from tools.network_monitor.data.monitor_worker import (  # noqa: PLC0415
            NetworkMonitorWorker,
        )

        return NetworkMonitorWorker(
            threat_checker=threat_checker,
            include_per_process=include_per_process,
            connection_repo=connection_repo,
        )

    @staticmethod
    def create_anomaly_service(
        process_traffic_repo: IProcessTrafficRepository | None = None,
        dns_repo: IDnsQueryRepository | None = None,
    ) -> AnomalyService:
        """Baut einen ``AnomalyService`` mit den Default-Repositories (Factory F-E).

        Haelt den ``data/``-Import (ProcessTrafficRepository/DnsQueryRepository) in
        der Application-Schicht — der GUI-Anomalie-Worker ruft nur diese Factory
        (gui→application), statt selbst ``data/``-Repos zu instanziieren.

        Die Repo-Konstruktion benoetigt einen aktiven ``KeyManager`` (verschluesselte
        DB); der Aufrufer ruft die Factory daher erst zur Worker-Startzeit (nach dem
        App-Bootstrap) und behandelt einen ``RuntimeError`` fail-soft.

        Args:
            process_traffic_repo: Optionales Repo (Tests); Default frisch erzeugt.
            dns_repo: Optionales DNS-Repo (Tests); Default frisch erzeugt.

        Returns:
            ``AnomalyService``, der die ``network_monitor``-DB liest.
        """
        from tools.network_monitor.application.anomaly_detector import (  # noqa: PLC0415
            AnomalyDetector,
            AnomalyService,
        )
        from tools.network_monitor.data.dns_query_repository import (  # noqa: PLC0415
            DnsQueryRepository,
        )
        from tools.network_monitor.data.process_traffic_repository import (  # noqa: PLC0415
            ProcessTrafficRepository,
        )

        return AnomalyService(
            process_traffic_repo
            if process_traffic_repo is not None
            else ProcessTrafficRepository(),
            detector=AnomalyDetector(),
            dns_repository=dns_repo if dns_repo is not None else DnsQueryRepository(),
        )

    @staticmethod
    def build_history_repositories() -> tuple[
        IConnectionRepository | None, IProcessTrafficRepository | None
    ]:
        """Baut die History-Repositories des Netzwerkmonitors fail-open (Factory).

        Haelt den ``data/``-Import (Connection-/ProcessTraffic-Repository) in der
        Application-Schicht — wie ``create_conversation_service``/
        ``create_anomaly_service`` — damit die Aufrufer nur ``gui→application``
        gehen (import-linter Contract „gui darf data nicht direkt importieren").

        Returns:
            ``(connection_repo, traffic_repo)``. Ein Element ist ``None``, wenn
            KeyManager/DB nicht verfuegbar sind — der Monitor laeuft dann ohne
            Persistenz/Export weiter (fail-open/, kein Lizenz-Gate).

        Effekt: EINZIGE Konstruktionsstelle der beiden Repos. Aufrufer sind
        ``NetworkMonitorTool.create_widget`` (Standalone-Tool) UND der in den
        Netzwerk-Scanner eingebettete Live-Tab (``network_scanner_widget``),
        damit BEIDE Pfade dieselbe 24h-Persistenz + den CSV-Export haben.
        Vorher bekam der eingebettete Tab kein Repository -> keine History,
        stiller Export-Button (Patrick-Live-Test 2026-06-25, D3).
        """
        from core.database.key_manager import KeyManagerError  # noqa: PLC0415
        from tools.network_monitor.data.connection_repository import (  # noqa: PLC0415
            ConnectionHistoryRepository,
        )
        from tools.network_monitor.data.process_traffic_repository import (  # noqa: PLC0415
            ProcessTrafficRepository,
        )

        repository: IConnectionRepository | None = None
        traffic_repo: IProcessTrafficRepository | None = None
        try:
            repository = ConnectionHistoryRepository()
        except (OSError, RuntimeError, KeyManagerError):
            repository = None
        try:
            traffic_repo = ProcessTrafficRepository()
        except (OSError, RuntimeError, KeyManagerError):
            traffic_repo = None
        return repository, traffic_repo
