"""network_monitor.application.whitelist_service — Whitelist-Pflege F-D-GUI).

Schmale, **DB-freie** Use-Case-Schicht über der nutzer-editierbaren
``whitelist.txt`` (Profil-Ordner). Bewusst getrennt vom:class:`ThreatFeedService`:
der öffnet die verschlüsselte Feed-Cache-DB (braucht ``KeyManager``) — nur um eine
Ausnahme in einer Textdatei einzutragen, wäre das unnötig schwer und in Test-/
Nicht-Windows-Umgebungen fragil. Der Bedrohungslisten-Tab nutzt diesen Service für
Anzeigen/Hinzufügen/Entfernen und den vollen:class:`ThreatFeedService` nur für den
eigentlichen Feed-Download.

Verantwortlich für:

  -:meth:`load` — aktuelle Whitelist-Netze lesen (Seed-Fallback bei frischer
    Installation).
  -:meth:`add` — ein Token strikt zu einem Netz parsen, deduplizieren und
    speichern (``WhitelistEntryError`` bei Müll/Duplikat).
  -:meth:`remove` — ein Netz entfernen und speichern.

Schichtzugehörigkeit: ``application/`` — orchestriert ``data/`` ohne GUI- oder
DB-Bezug.

Author: Patrick Riederich
Version: 1.0 F-D-GUI)
"""

from __future__ import annotations

from pathlib import Path

from core.logger import get_logger
from tools.network_monitor.data.blocklist_loader import (
    load_whitelist,
    parse_network_token,
    save_whitelist,
)
from tools.network_monitor.domain.exceptions import WhitelistEntryError
from tools.network_monitor.domain.models import Network

_log = get_logger(__name__)

#: Kleinste erlaubte Präfixlänge einer Whitelist-Ausnahme (Schutz gegen Blanket-
#: Override). Spiegelt bewusst die Feed-Schwelle (``MIN_FEED_PREFIX_*`` in
#: ``data.threat_feed_client``): eine zu weit gefasste Ausnahme — allen voran
#: ``0.0.0.0/0`` (Präfix 0) bzw. ``::/0`` — würde JEDEN Treffer aufheben und damit
#: die Bedrohungserkennung still abschalten (fail-quiet). ``/8`` (IPv4) bzw. ``/32``
#: (IPv6) lassen legitime interne Bereiche zu, blocken aber den Default-Route-Footgun.
_MIN_WHITELIST_PREFIX_V4: int = 8
_MIN_WHITELIST_PREFIX_V6: int = 32


class WhitelistService:
    """Pflegt die manuelle Whitelist (Override gegen False-Positives), DB-frei."""

    def __init__(self, whitelist_path: Path | None = None) -> None:
        """Initialisiert den Service.

        Args:
            whitelist_path: Optionaler Pfad zur Whitelist (Tests). ``None`` nutzt
                die nutzer-editierbare Profil-Datei
                (:func:`data.blocklist_loader.user_whitelist_path`).
        """
        self._path = whitelist_path

    def load(self) -> list[Network]:
        """Liest die aktuellen Whitelist-Netze (Seed-Fallback bei frischem Profil)."""
        return load_whitelist(self._path)

    def add(self, token: str) -> Network:
        """Parst ein Token strikt zu einem Netz, dedupliziert und speichert es.

        Args:
            token: Roh-Eingabe des Nutzers (IP oder CIDR, mit/ohne Port-Suffix).

        Returns:
            Das hinzugefügte Netz (kanonisch).

        Raises:
            WhitelistEntryError: Wenn ``token`` nicht als IP/CIDR parst, zu weit
                gefasst ist (Blanket-Override) oder das Netz bereits in der
                Whitelist steht.
        """
        cleaned = token.strip()
        network = parse_network_token(cleaned)
        if network is None:
            raise WhitelistEntryError(
                f"„{cleaned}“ ist keine gültige IP-Adresse oder CIDR-Notation."
            )
        # Gesetzte Host-Bits (z. B. "203.0.113.10/24") werden vom toleranten Parser
        # still zum Netz erweitert -> ein als Einzel-Host gemeinter Tippfehler würde
        # unbemerkt einen ganzen Bereich whitelisten. Strikt nachprüfen und ablehnen
        #: der Nutzer soll bewusst die Netz-Adresse ODER die Host-IP eintragen.
        if parse_network_token(cleaned, strict=True) is None:
            raise WhitelistEntryError(
                f"„{cleaned}“ hat gesetzte Host-Bits. Meinten Sie das Netz {network} "
                "oder eine einzelne Adresse? Tragen Sie die Netz-Adresse oder die "
                "Host-IP ein."
            )
        floor = (
            _MIN_WHITELIST_PREFIX_V4
            if network.version == 4
            else _MIN_WHITELIST_PREFIX_V6
        )
        if network.prefixlen < floor:
            raise WhitelistEntryError(
                f"{network} ist zu weit gefasst — ein so breiter Bereich würde die "
                "Bedrohungserkennung praktisch abschalten. Tragen Sie einzelne "
                "Adressen oder enge Bereiche ein."
            )
        current = self.load()
        if any(str(existing) == str(network) for existing in current):
            raise WhitelistEntryError(f"{network} steht bereits in der Whitelist.")
        current.append(network)
        save_whitelist(current, self._path)
        return network

    def remove(self, network: Network) -> None:
        """Entfernt ein Netz aus der Whitelist und speichert (No-op wenn fehlend).

        Args:
            network: Das zu entfernende Netz (Vergleich über die kanonische Form).
        """
        target = str(network)
        remaining = [n for n in self.load() if str(n) != target]
        save_whitelist(remaining, self._path)
