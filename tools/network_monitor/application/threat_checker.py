"""network_monitor.application.threat_checker — IP-Blocklist-Abgleich (Pro-Feature).

Implementiert `IBlocklistProvider` rein in-memory. Die Einträge werden aus der
lokalen ``blocklist.txt`` **plus** den F-D) gecachten abuse.ch-Feeds
zusammengeführt und in diesen Checker injiziert; eine manuelle ``whitelist.txt``
hebt Treffer wieder auf (Override gegen False-Positives).

Unterstützt plain IPv4 (``1.2.3.4``), IPv4-CIDR (``10.0.0.0/8``), IPv6 und
IPv6-CIDR.

Thread-Sicherheit: Einträge UND Whitelist liegen in **einem** Tupel
``self._state``;:meth:`replace_entries` tauscht es in **einer** Attribut-Zuweisung
(GIL-atomar). Ein paralleler Leser im Monitor-Worker liest genau diese eine
Referenz und sieht stets ein konsistentes (Einträge, Whitelist)-Paar — nie einen
Mischzustand aus altem und neuem Stand. Daher kommt der Live-Refresh F-D)
ohne Lock aus.

Author: Patrick Riederich
Version: 1.1 F-D — Feed-Merge, Whitelist-Override, Live-Refresh)
"""

from __future__ import annotations

import ipaddress

from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IBlocklistProvider
from tools.network_monitor.domain.models import Network


class ThreatChecker(IBlocklistProvider):
    """Prüft IPs gegen eine vorgeladene In-Memory-Blocklist + Whitelist-Override.

    Attributes:
        _state: Tupel ``(entries, whitelist)``. ``entries`` ist eine Liste aus
            (network, reason)-Tupeln (``network`` stets ein ``ip_network``-Objekt);
            ``whitelist`` eine Liste von Netzen, die einen Match wieder aufheben.
            Wird als EINE Einheit atomar getauscht (Thread-Sicherheit ohne Lock).
    """

    def __init__(
        self,
        entries: list[tuple[Network, str]] | None = None,
        whitelist: list[Network] | None = None,
    ) -> None:
        """Initialisiert den Checker.

        Args:
            entries: Vorbereitete Liste von (Netzwerk, Grund)-Paaren. Wird
                typischerweise vom ``ThreatFeedService`` (Blocklist + Feeds)
                erzeugt.
            whitelist: Netze, die einen Treffer überschreiben (False-Positive-
                Override aus ``data.blocklist_loader.load_whitelist``).
        """
        self._log = get_logger(__name__)
        self._state: tuple[list[tuple[Network, str]], list[Network]] = (
            list(entries or []),
            list(whitelist or []),
        )

    def replace_entries(
        self,
        entries: list[tuple[Network, str]],
        whitelist: list[Network] | None = None,
    ) -> None:
        """Tauscht Einträge (und optional Whitelist) atomar aus (Live-Refresh).

        Baut das neue ``(entries, whitelist)``-Paar und weist es in **einer**
        Attribut-Zuweisung zu — unter dem GIL atomar, daher thread-sicher
        gegenüber einem parallel lesenden Monitor-Worker (kein Lock nötig). Wird
        vom Feed-Refresh-Worker F-D) nach einem erfolgreichen Update
        aufgerufen.

        Args:
            entries: Neue (Netzwerk, Grund)-Paare (ersetzt die bisherigen).
            whitelist: Neue Whitelist; ``None`` lässt die bestehende unverändert.
        """
        current_whitelist = self._state[1]
        new_whitelist = list(whitelist) if whitelist is not None else current_whitelist
        self._state = (list(entries), new_whitelist)  # atomarer Ref-Swap (GIL)

    def replace_whitelist(self, whitelist: list[Network]) -> None:
        """Tauscht **nur** die Whitelist atomar aus (Einträge bleiben unverändert).

        Pendant zu:meth:`replace_entries` für den Fall, dass der Nutzer im
        Bedrohungslisten-Tab F-D-GUI) eine Ausnahme hinzufügt/entfernt:
        die teuren Blocklist-/Feed-Einträge müssen dafür nicht neu gebaut werden.
        Baut das neue ``(entries, whitelist)``-Paar und weist es in **einer**
        Attribut-Zuweisung zu (GIL-atomar, thread-sicher ohne Lock).

        Args:
            whitelist: Neue Whitelist-Netze (ersetzt die bisherigen).
        """
        self._state = (self._state[0], list(whitelist))  # atomarer Ref-Swap (GIL)

    def is_suspicious(self, ip: str) -> tuple[bool, str]:
        """Prüft ob ``ip`` gegen irgendeinen Blocklist-Eintrag matcht.

        Reihenfolge: Whitelist hat Vorrang (ein Treffer dort gilt nie als
        verdächtig). Leere Strings und nicht-parsebare IPs gelten als nicht
        verdächtig (Fail-open), damit LISTEN-Sockets ohne Remote-IP die Tabelle
        nicht rot färben.

        Args:
            ip: Zu prüfende IP-Adresse (IPv4 oder IPv6, dotted/colonized).

        Returns:
            Tupel (matched, reason). Bei ``matched=False`` ist ``reason=""``.
        """
        if not ip:
            return (False, "")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, "")

        # EIN atomarer Read der Zustands-Referenz → konsistentes (Einträge,
        # Whitelist)-Paar, auch wenn replace_entries parallel tauscht.
        entries, whitelist = self._state

        for network in whitelist:
            if addr.version == network.version and addr in network:
                return (False, "")

        for network, reason in entries:
            if addr.version != network.version:
                continue
            if addr in network:
                return (True, reason)
        return (False, "")

    def entry_count(self) -> int:
        """Anzahl aktuell geladener Blocklist-Einträge (ohne Whitelist)."""
        return len(self._state[0])

    def whitelist_count(self) -> int:
        """Anzahl aktuell geladener Whitelist-Netze (Ausnahmen)."""
        return len(self._state[1])
