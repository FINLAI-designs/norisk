"""
nmap_scanner — Optionaler nmap-basierter Scanner.

Ruft nmap als Subprocess auf und parst die XML-Ausgabe.
Nur `-sV` (Service-Detection) — kein SYN-Scan, keine Root-Rechte nötig.

Sicherheitsdesign:
  - Nur -sV Flag — kein -sS/--script/--os-detection
  - Port-Liste wird als kommaseparierter String übergeben (kein Shell-Injection)
  - subprocess.run mit Liste (kein shell=True)
  - Timeout: 120s pro Host

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import defusedxml.ElementTree as ET

from core.exceptions import ExternalToolError
from core.logger import get_logger
from tools.network_scanner.domain.interfaces import IScannerBackend
from tools.network_scanner.domain.models import HostInfo, PortInfo, PortState

log = get_logger(__name__)

_NMAP_TIMEOUT = 120  # Sekunden

# Standard-Windows-Installationsorte von nmap. Der Installer nimmt nmap NICHT
# immer in den PATH auf (Option abwaehlbar; oder die App lief schon vor der
# nmap-Installation) — dann findet ``shutil.which("nmap")`` es nicht, obwohl es
# installiert ist. Das war die Ursache fuer "nmap-Erkennung tot" (Patrick-
# Live-Test 2026-06-25): nmap in Program Files, aber Checkbox disabled.
_WINDOWS_NMAP_PATHS: tuple[str, ...] = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


class NmapScanner(IScannerBackend):
    """nmap-basierter Port-Scanner mit Service-Erkennung (-sV).

    Parst nmap XML-Output und liefert HostInfo-Objekte.
    Fällt zurück auf SocketScanner wenn nmap nicht gefunden wird.

    Args:
        nmap_pfad: Pfad zum nmap-Binary (Standard: aus PATH).
    """

    def __init__(self, nmap_pfad: str = "nmap") -> None:
        """Initialisiert den NmapScanner und loest den nmap-Pfad auf."""
        self._nmap_pfad: str | None = self._resolve_nmap_path(nmap_pfad)

    @staticmethod
    def _resolve_nmap_path(candidate: str) -> str | None:
        """Loest den nmap-Pfad auf: erst PATH, dann Standard-Windows-Orte.

        Args:
            candidate: Bevorzugter Name/Pfad (Default ``"nmap"`` = PATH-Lookup).

        Returns:
            Absoluter Pfad zum nmap-Binary oder ``None``, wenn nmap weder im
            PATH noch an einem Standard-Windows-Installationsort liegt.
        """
        found = shutil.which(candidate)
        if found:
            return found
        # Expliziter Pfad uebergeben, der existiert?
        if candidate and candidate != "nmap" and Path(candidate).is_file():
            return candidate
        # Windows-Fallback: Standard-Installationsorte direkt pruefen.
        for pfad in _WINDOWS_NMAP_PATHS:
            if Path(pfad).is_file():
                return pfad
        return None

    def ist_verfuegbar(self) -> bool:
        """Prüft ob ein nutzbares nmap-Binary gefunden wurde.

        Returns:
            True wenn nmap im PATH ODER an einem Standard-Windows-
            Installationsort liegt.
        """
        return self._nmap_pfad is not None

    def scan_host(
        self,
        host: str,
        ports: list[int],
    ) -> HostInfo:
        """Scannt einen Host mit nmap -sV.

        Args:
            host: IP-Adresse oder Hostname.
            ports: Liste der zu scannenden Port-Nummern.

        Returns:
            HostInfo mit Service-Informationen aus nmap.

        Raises:
            RuntimeError: Wenn nmap nicht verfügbar oder fehlgeschlagen ist.
        """
        if not self.ist_verfuegbar():
            raise ExternalToolError("nmap nicht gefunden — SocketScanner verwenden")

        port_str = ",".join(str(p) for p in ports)
        t0 = time.monotonic()

        # Kein shell=True — Argumente als Liste (kein Injection-Risiko)
        cmd = [
            self._nmap_pfad,
            "-sV",  # Service-Version-Detection
            "-p",
            port_str,
            "-oX",
            "-",  # XML-Ausgabe auf stdout
            "--open",  # Nur offene Ports
            host,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=_NMAP_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("nmap Timeout nach %ds für %s", _NMAP_TIMEOUT, host)
            return HostInfo(host=host, erreichbar=False, scan_dauer_s=_NMAP_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("nmap fehlgeschlagen: %s", type(exc).__name__)
            return HostInfo(host=host, erreichbar=False)

        dauer = time.monotonic() - t0

        if proc.returncode != 0:
            log.warning("nmap exit %d für %s", proc.returncode, host)
            return HostInfo(host=host, erreichbar=False, scan_dauer_s=dauer)

        return self._parse_xml(host, proc.stdout, dauer)

    def _parse_xml(
        self,
        host: str,
        xml_bytes: bytes,
        dauer: float,
    ) -> HostInfo:
        """Parst nmap XML-Ausgabe in ein HostInfo-Objekt.

        Args:
            host: Gescannter Host-Name (Fallback wenn XML fehlt).
            xml_bytes: nmap XML-Ausgabe als Bytes.
            dauer: Scan-Dauer in Sekunden.

        Returns:
            Geparster HostInfo.
        """
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            log.warning("nmap XML Parse-Fehler: %s", exc)
            return HostInfo(host=host, erreichbar=False, scan_dauer_s=dauer)

        offene_ports: list[PortInfo] = []
        erreichbar = False
        betriebssystem = ""

        host_elem = root.find(".//host")
        if host_elem is None:
            return HostInfo(host=host, erreichbar=False, scan_dauer_s=dauer)

        # Host-Zustand
        status = host_elem.find("status")
        if status is not None and status.get("state") == "up":
            erreichbar = True

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                portid = int(port_elem.get("portid", 0))
                service_elem = port_elem.find("service")
                service_name = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    if product:
                        service_name = f"{service_name} ({product} {version})".strip()

                offene_ports.append(
                    PortInfo(
                        port=portid,
                        state=PortState.OPEN,
                        service=service_name,
                    )
                )

        log.debug(
            "nmap %s: %d offene Ports in %.1fs",
            host,
            len(offene_ports),
            dauer,
        )
        return HostInfo(
            host=host,
            erreichbar=erreichbar,
            offene_ports=offene_ports,
            betriebssystem=betriebssystem,
            scan_dauer_s=dauer,
        )
