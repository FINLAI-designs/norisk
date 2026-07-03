"""cert_monitor_service — Orchestriert Scans und Domain-Verwaltung.

Schichtzugehörigkeit: application/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.logger import get_logger
from tools.cert_monitor.domain.models import CertInfo, CertStatus

_log = get_logger(__name__)


class CertMonitorService:
    """Orchestriert Zertifikats-Scans, Domain-Verwaltung und Persistenz.

    Attributes:
        _scanner: CertScanner für SSL-Verbindungen.
        _repo: CertRepository für Persistenz.
    """

    def __init__(self, scanner, repo, ki_todo_emitter=None) -> None:
        """Initialisiert den CertMonitorService.

        Args:
            scanner: CertScanner-Instanz.
            repo: CertRepository-Instanz.
            ki_todo_emitter: Optionaler ``KiTodoEmitter``. Default
                wird lazy gebaut.
        """
        self._scanner = scanner
        self._repo = repo
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import KiTodoEmitter  # noqa: PLC0415
            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    @classmethod
    def create_default(cls) -> CertMonitorService:
        """Baut einen voll verdrahteten Service mit Default-Adaptern (headless).

        Erlaubt Konsumenten ausserhalb des Tools (z.B. den Fleet-Agent) den
        Service ueber die application-Schicht zu erzeugen, ohne ``data/`` direkt
        zu importieren (Schicht-Vertrag). Der Scanner wird nur fuer Live-Scans
        gebraucht; der reine Lese-Pfad (:meth:`lade_letzte_ergebnisse`) nutzt ihn
        nicht und loest daher keinen Netzwerk-Zugriff aus.

        Returns:
            Ein einsatzbereiter:class:`CertMonitorService`.
        """
        from tools.cert_monitor.data.cert_repository import (
            CertRepository,  # noqa: PLC0415
        )
        from tools.cert_monitor.data.cert_scanner import CertScanner  # noqa: PLC0415

        return cls(scanner=CertScanner(), repo=CertRepository())

    def lade_domains(self) -> list[tuple[str, int]]:
        """Lädt alle überwachten Domains.

        Returns:
            Liste von (domain, port)-Tupeln.
        """
        return self._repo.lade_domains()

    def domain_hinzufuegen(self, domain: str, port: int = 443) -> None:
        """Fügt eine Domain zur Überwachungsliste hinzu.

        Args:
            domain: Hostname (ohne Protokoll).
            port: TLS-Port.
        """
        domain = domain.strip().lower().removeprefix("https://").removeprefix("http://")
        domain = domain.split("/")[0]  # Pfad entfernen
        self._repo.fuge_domain_hinzu(domain, port)

    def domain_entfernen(self, domain: str, port: int = 443) -> None:
        """Entfernt eine Domain aus der Überwachungsliste.

        Args:
            domain: Hostname.
            port: TLS-Port.
        """
        self._repo.entferne_domain(domain, port)

    def scanne_domain(self, domain: str, port: int = 443) -> CertInfo:
        """Scannt eine Domain und speichert das Ergebnis.

        Args:
            domain: Hostname.
            port: TLS-Port.

        Returns:
            CertInfo mit Scan-Ergebnis.
        """
        if not external_fetches_allowed():
            _log.debug("Cert-Scan uebersprungen: %s", OFFLINE_HINT)
            return CertInfo(
                domain=domain,
                port=port,
                status=CertStatus.FEHLER,
                fehler_meldung=OFFLINE_HINT,
            )
        _log.info("Scanne Zertifikat: %s:%d", domain, port)
        cert = self._scanner.scan(domain, port)
        self._repo.speichere_ergebnis(cert)
        return cert

    def scanne_alle(
        self,
        progress_callback=None,
    ) -> list[CertInfo]:
        """Scannt alle überwachten Domains.

        Args:
            progress_callback: Optionale Funktion(current, total, domain) für Fortschritts-Updates.

        Returns:
            Liste der CertInfo-Ergebnisse.
        """
        domains = self._repo.lade_domains()
        ergebnisse: list[CertInfo] = []

        for i, (domain, port) in enumerate(domains):
            if progress_callback:
                progress_callback(i, len(domains), domain)
            try:
                cert = self.scanne_domain(domain, port)
            except Exception as exc:  # noqa: BLE001 — ein Ziel darf den Batch nie abbrechen
                _log.exception("Cert-Scan für %s:%d fehlgeschlagen", domain, port)
                cert = CertInfo(
                    domain=domain,
                    port=port,
                    status=CertStatus.FEHLER,
                    fehler_meldung=str(exc),
                )
            ergebnisse.append(cert)

        if progress_callback:
            progress_callback(len(domains), len(domains), "")

        # (a)+(b): KiTodo-Hook nach Scan-Complete fuer alle Cert-
        # Eintraege gesammelt (Batch ist effizienter als pro Domain).
        if ergebnisse:
            from tools.cert_monitor.application.storytelling_adapter import (  # noqa: PLC0415
                emit_to_ki_emitter,
            )
            emit_to_ki_emitter(self._ki_todo_emitter, ergebnisse)

        return ergebnisse

    def lade_letzte_ergebnisse(self) -> list[CertInfo]:
        """Lädt die zuletzt gespeicherten Scan-Ergebnisse aus der DB.

        Returns:
            Liste der gespeicherten CertInfo-Objekte.
        """
        return self._repo.lade_ergebnisse()
