"""
network_service — Use Cases für den Netzwerk-Scanner.

Orchestriert Scanner-Backend, Risiko-Analyse und Persistenz.
Wählt automatisch zwischen SocketScanner und NmapScanner.

Sicherheitsdesign:
  - Ziel-Hosts werden validiert (keine Befehlsinjection)
  - Scan-Inhalte werden nicht geloggt

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime

from core.exceptions import ValidationError
from core.logger import get_logger
from tools.network_scanner.data.socket_scanner import DEFAULT_PORTS
from tools.network_scanner.domain.analyzer import analysiere_ports
from tools.network_scanner.domain.interfaces import IScannerBackend, IScanRepository
from tools.network_scanner.domain.models import (
    NetworkDiscoveryResult,
    NetworkScanResult,
)

log = get_logger(__name__)

# Erlaubte Zeichen in Hostnames: Buchstaben, Ziffern, Punkt, Bindestrich
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")
_MAX_HOSTNAME_LEN = 253


class NetworkService:
    """Use-Case-Service für den Netzwerk-Scanner.

    Koordiniert Scanner-Auswahl, Risiko-Analyse und Persistenz.

    Args:
        scanner: Primäres Scanner-Backend.
        repo: Repository für Scan-Ergebnisse.
        nmap_scanner: Optionaler nmap-Scanner (verwendet wenn verfügbar).
    """

    def __init__(
        self,
        scanner: IScannerBackend,
        repo: IScanRepository,
        nmap_scanner: IScannerBackend | None = None,
        ki_todo_emitter: object | None = None,
    ) -> None:
        """Initialisiert den NetworkService."""
        self._scanner = scanner
        self._repo = repo
        self._nmap_scanner = nmap_scanner
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import KiTodoEmitter  # noqa: PLC0415
            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    def starte_scan(
        self,
        ziel: str,
        ports: list[int] | None = None,
        nmap_bevorzugt: bool = False,
        *,
        extern_erlaubt: bool = False,
    ) -> NetworkScanResult:
        """Startet einen Port-Scan auf dem angegebenen Ziel.

        Validiert das Ziel, wählt das Backend, führt den Scan durch,
        analysiert die Risiken und speichert das Ergebnis.

        Standardmäßig sind nur interne Ziele erlaubt (RFC1918, Loopback,
        Link-Local). Ein Scan gegen externe Hosts ohne Auftrag erfüllt
        in DE/AT den Tatbestand des §202c StGB / §126 ÖStGB ("Ausspähen
        von Daten" / Hacker-Paragraph). Das GUI muss den User vor dem
        Setzen von ``extern_erlaubt=True`` explizit bestätigen lassen,
        dass er einen schriftlichen Pentest-Auftrag für das Ziel hat.

        Args:
            ziel: IP-Adresse oder Hostname.
            ports: Zu scannende Ports. None = DEFAULT_PORTS.
            nmap_bevorzugt: True = nmap verwenden falls verfügbar.
            extern_erlaubt: True erlaubt öffentliche IPs / unbekannte
                            Hostnames. Default False = strikt intern.
                            MUSS aus einer expliziten User-Bestätigung
                            stammen, nicht hartkodiert.

        Returns:
            NetworkScanResult mit analysierten Ports.

        Raises:
            ValueError: Wenn das Ziel ungültig ist oder eine
                externe IP ohne ``extern_erlaubt=True`` gescannt
                werden soll.
        """
        ziel = ziel.strip()
        self._validiere_ziel(ziel)
        if not extern_erlaubt and not self._ist_intern(ziel):
            raise ValidationError(
                f"'{ziel}' ist kein internes Ziel (kein RFC1918 / Loopback / "
                "Link-Local). Externe Scans erfordern eine explizite "
                "Bestätigung im GUI (Pentest-Auftrag erforderlich, §202c StGB)."
            )
        if extern_erlaubt and not self._ist_intern(ziel):
            log.warning(
                "Externer Scan freigegeben: %s — User-Bestätigung wird "
                "vorausgesetzt (Pentest-Auftrag).",
                ziel,
            )
        ports = ports or DEFAULT_PORTS

        backend = self._waehle_backend(nmap_bevorzugt)
        scanner_typ = "nmap" if backend is not self._scanner else "socket"

        gestartet = datetime.now(UTC)
        t0 = time.monotonic()
        log.info(
            "Scan gestartet: %s (%d Ports, Backend: %s)",
            ziel,
            len(ports),
            scanner_typ,
        )

        host_info = backend.scan_host(ziel, ports)

        # Risiko-Analyse
        host_info.offene_ports = analysiere_ports(host_info.offene_ports)

        beendet = datetime.now(UTC)
        dauer = time.monotonic() - t0

        result = NetworkScanResult(
            ziel=ziel,
            hosts=[host_info],
            gestartet_am=gestartet,
            beendet_am=beendet,
            scanner_typ=scanner_typ,
        )

        log.info(
            "Scan abgeschlossen: %s — %d offene Ports in %.1fs",
            ziel,
            result.anzahl_offene_ports,
            dauer,
        )

        try:
            self._repo.speichere_scan(result)
        except (OSError, RuntimeError) as exc:
            log.warning("Scan-Speicherung fehlgeschlagen: %s", type(exc).__name__)

        # (a)+(b): KiTodo-Hook nach Scan-Complete.
        from tools.network_scanner.application.storytelling_adapter import (  # noqa: PLC0415
            emit_to_ki_emitter,
        )
        emit_to_ki_emitter(self._ki_todo_emitter, result)

        return result

    def discover_hosts(
        self,
        subnetz: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> NetworkDiscoveryResult:
        """Fuehrt einen Host-Discovery-Scan im angegebenen Subnetz aus.

 (RUN2-GUI): Service-Wrapper um:class:`NetworkDiscovery`,
        damit die GUI nicht direkt aus ``data/`` instanziieren muss.

        Args:
            subnetz: Subnetz in CIDR-Notation (z. B. ``192.168.0.0/24``).
            progress_callback: Optionaler Fortschritts-Callback
                ``(aktuell, gesamt)``.

        Returns:
            ``NetworkDiscoveryResult`` mit allen gefundenen Hosts.
        """
        from tools.network_scanner.data.network_discovery import (  # noqa: PLC0415
            NetworkDiscovery,
        )

        discovery = NetworkDiscovery()
        return discovery.discover_hosts(
            subnetz, progress_callback=progress_callback
        )

    def eigene_netzwerk_info(self) -> tuple[str, str, str]:
        """Liefert ``(eigene_ip, subnetz_cidr, gateway_ip)`` des Hosts.

        Service-Wrapper um:class:`NetworkDiscovery`, damit die
        GUI keine ``data/``-Direktimporte mehr braucht.

        Returns:
            Tupel ``(eigene_ip, subnetz_cidr, gateway_ip)``. Bei Fehlern
            ``("", "", "")``.
        """
        from tools.network_scanner.data.network_discovery import (  # noqa: PLC0415
            NetworkDiscovery,
        )

        return NetworkDiscovery().eigene_netzwerk_info()

    def lade_letzte_scans(self, limit: int = 10) -> list[NetworkScanResult]:
        """Lädt die zuletzt gespeicherten Scans.

        Args:
            limit: Maximale Anzahl.

        Returns:
            Scan-Ergebnisse, neueste zuerst.
        """
        try:
            return self._repo.lade_letzte_scans(limit=limit)
        except (OSError, RuntimeError) as exc:
            log.warning("Scan-Laden fehlgeschlagen: %s", type(exc).__name__)
            return []

    def delete_scan(self, scan_id: str) -> bool:
        """Löscht einen einzelnen Scan.

        Args:
            scan_id: ID des zu löschenden Scans.

        Returns:
            True wenn gelöscht, False wenn nicht gefunden.
        """
        try:
            return self._repo.delete_scan(scan_id)  # type: ignore[attr-defined]
        except (OSError, RuntimeError) as exc:
            log.warning("Scan-Löschung fehlgeschlagen: %s", type(exc).__name__)
            return False

    def delete_all_scans(self) -> int:
        """Löscht alle gespeicherten Scans.

        Returns:
            Anzahl gelöschter Einträge.
        """
        try:
            return self._repo.delete_all_scans()  # type: ignore[attr-defined]
        except (OSError, RuntimeError) as exc:
            log.warning("Verlauf-Löschung fehlgeschlagen: %s", type(exc).__name__)
            return 0

    def nmap_verfuegbar(self) -> bool:
        """Prüft ob nmap als Backend verfügbar ist.

        Returns:
            True wenn nmap gefunden wurde.
        """
        return self._nmap_scanner is not None and self._nmap_scanner.ist_verfuegbar()

    def _waehle_backend(self, nmap_bevorzugt: bool) -> IScannerBackend:
        """Wählt das optimale Scanner-Backend.

        Args:
            nmap_bevorzugt: True = nmap bevorzugen.

        Returns:
            Ausgewähltes Backend.
        """
        if nmap_bevorzugt and self.nmap_verfuegbar():
            return self._nmap_scanner  # type: ignore[return-value]
        return self._scanner

    @staticmethod
    def _validiere_ziel(ziel: str) -> None:
        """Validiert ein Scan-Ziel gegen bekannte Injektionsmuster.

        Erlaubt: gültige IPv4/IPv6-Adressen und valide Hostnames.

        Args:
            ziel: Zu validierender Ziel-String.

        Raises:
            ValueError: Wenn das Ziel ungültig oder gefährlich ist.
        """
        if not ziel:
            raise ValidationError("Kein Scan-Ziel angegeben")

        if len(ziel) > _MAX_HOSTNAME_LEN:
            raise ValidationError("Ziel zu lang")

        # IPv4/IPv6 direkt erlaubt
        try:
            ipaddress.ip_address(ziel)
            return
        except ValueError:
            pass

        # Hostname-Validierung
        if not _HOSTNAME_RE.match(ziel):
            raise ValidationError(
                f"Ungültiges Scan-Ziel: '{ziel}' enthält unerlaubte Zeichen"
            )

    @staticmethod
    def _ist_intern(ziel: str) -> bool:
        """Prüft, ob ein Ziel als "internes Netz" gilt.

        Internes Ziel = RFC1918 (10/8, 172.16/12, 192.168/16),
        Loopback (127/8,::1), Link-Local (169.254/16, fe80::/10),
        Multicast (224/4) oder unspecified (0.0.0.0/8). Hostnames werden
        IMMER als extern behandelt (keine DNS-Auflösung im Validator —
        wäre selbst ein Netzwerk-Aufruf vor dem User-Consent).

        Effekt: wird in:meth:`starte_scan` für die §202c-Schranke
        verwendet — Default blockiert alles außer reinen Internal-IP-
        Targets. Hostnames müssen via ``extern_erlaubt=True`` aus
        explizitem User-Consent freigeschaltet werden.

        Args:
            ziel: Validierter String aus:meth:`_validiere_ziel`.

        Returns:
            True wenn IP-Literal mit privatem/loopback-Charakter,
            sonst False.
        """
        try:
            ip = ipaddress.ip_address(ziel)
        except ValueError:
            # Hostname → unbekannt, sicherheitshalber als extern
            return False
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        )


def create_default_network_service() -> NetworkService:
    """Baut einen produktiv verdrahteten:class:`NetworkService` (Standard-Wiring).

    Faktorisiert die Default-Komponenten-Verdrahtung (Socket-/Nmap-Backend +
    Scan-Repository) an EINER Stelle in der application-Schicht. Cross-Tool-
    Konsumenten (z. B. ``security_scoring`` für die Audit-Vorbefuellung)
    beziehen den Service dadurch über die application-Schicht des Netzwerk-Scanners
    statt direkt dessen ``data/``-Klassen zu importieren — die hexagonale
    Schichtgrenze bleibt gewahrt (kein Cross-Tool ``application → data``, A-1).

    Returns:
        Ein einsatzbereiter:class:`NetworkService` mit Produktiv-Backends.
    """
    from tools.network_scanner.data.nmap_scanner import NmapScanner  # noqa: PLC0415
    from tools.network_scanner.data.scan_repository import (
        ScanRepository,  # noqa: PLC0415
    )
    from tools.network_scanner.data.socket_scanner import SocketScanner  # noqa: PLC0415

    return NetworkService(
        scanner=SocketScanner(),
        repo=ScanRepository(),
        nmap_scanner=NmapScanner(),
    )
