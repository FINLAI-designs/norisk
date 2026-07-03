"""
interfaces — Abstrakte Ports für das Cyberrisiko-Dashboard.

Definiert die Schnittstellen, die von den data/-Adaptern
implementiert werden müssen. Keine Außen-Abhängigkeiten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import datetime

from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
    TechStackEintrag,
    YouTubeVideo,
)


class ICacheRepository(ABC):
    """Port für den lokalen Meldungs-Cache."""

    @abstractmethod
    def speichere_meldungen(self, meldungen: list[CyberMeldung]) -> None:
        """Speichert Meldungen im Cache.

        Args:
            meldungen: Liste der zu speichernden Meldungen.
        """
        ...

    @abstractmethod
    def lade_meldungen(
        self,
        schweregrad: Schweregrad | None = None,
        quelle: QuelleTyp | None = None,
        limit: int = 100,
    ) -> list[CyberMeldung]:
        """Lädt Meldungen aus dem Cache.

        Args:
            schweregrad: Optionaler Filter nach Schweregrad.
            quelle: Optionaler Filter nach Quelle.
            limit: Maximale Anzahl zurückgegebener Meldungen.

        Returns:
            Meldungen, neueste zuerst.
        """
        ...

    @abstractmethod
    def speichere_videos(self, videos: list[YouTubeVideo]) -> None:
        """Speichert Videos im Cache.

        Args:
            videos: Liste der zu speichernden Videos.
        """
        ...

    @abstractmethod
    def lade_videos(self, limit: int = 10) -> list[YouTubeVideo]:
        """Lädt Videos aus dem Cache.

        Args:
            limit: Maximale Anzahl zurückgegebener Videos.

        Returns:
            Videos, neueste zuerst.
        """
        ...

    @abstractmethod
    def ist_frisch(self) -> bool:
        """Prüft ob der Cache innerhalb der TTL aktuell ist.

        Returns:
            True wenn der Cache weniger als 1 Stunde alt ist.
        """
        ...

    @abstractmethod
    def speichere_cves(self, cves: list[CveEintrag]) -> None:
        """Speichert CVE-Einträge im Cache.

        Args:
            cves: Liste der zu speichernden CVE-Einträge.
        """
        ...

    @abstractmethod
    def lade_cves(
        self,
        schweregrad: str | None = None,
        nur_kev: bool = False,
        limit: int = 50,
    ) -> list[CveEintrag]:
        """Lädt CVE-Einträge aus dem Cache.

        Args:
            schweregrad: Optionaler Filter (CRITICAL/HIGH/MEDIUM/LOW).
            nur_kev: True = nur CISA KEV CVEs zurückgeben.
            limit: Maximale Anzahl zurückgegebener Einträge.

        Returns:
            CVE-Einträge, neueste zuerst.
        """
        ...

    @abstractmethod
    def zaehle_cves_nach_schweregrad(self) -> dict[str, int]:
        """Zählt CVEs der letzten 24h nach Schweregrad.

        Returns:
            Dict mit Schweregrad als Key und Anzahl als Value.
            Enthält zusätzlich "kev" für CISA KEV CVEs.
        """
        ...

    # ------------------------------------------------------------------
    # Read/Unread/Snooze-State (2026-05-28 Phishing-Radar-Refactor)
    # ------------------------------------------------------------------

    @abstractmethod
    def markiere_gelesen(self, guids: Iterable[str]) -> None:
        """Markiert Meldungen als gelesen.

        Idempotent — mehrfaches Setzen aktualisiert ``gelesen_am`` nicht.

        Args:
            guids: Iterable der zu markierenden Meldungs-GUIDs.
        """
        ...

    @abstractmethod
    def markiere_ungelesen(self, guids: Iterable[str]) -> None:
        """Setzt den Gelesen-Status zurueck.

        Args:
            guids: Iterable der zu markierenden Meldungs-GUIDs.
        """
        ...

    @abstractmethod
    def schiebe_auf(self, guid: str, bis: datetime, quelle: QuelleTyp) -> None:
        """Schiebt eine Meldung bis zu einem Zeitpunkt auf.

        Args:
            guid: Meldungs-GUID.
            bis: Zeitpunkt ab dem die Meldung wieder sichtbar wird.
            quelle: Quelle der Meldung (fuer Index/Counts).
        """
        ...

    @abstractmethod
    def lade_state_fuer(self, guids: Iterable[str]) -> dict[str, tuple[datetime | None, datetime | None]]:
        """Lädt Read/Snooze-State fuer eine Menge von GUIDs.

        Args:
            guids: Iterable der Meldungs-GUIDs.

        Returns:
            Dict mit GUID als Key und ``(gelesen_am, snooze_bis)`` als Wert.
            Fehlende GUIDs liefern ``(None, None)``.
        """
        ...

    @abstractmethod
    def zaehle_ungelesene(self, quellen: Iterable[QuelleTyp]) -> int:
        """Zaehlt ungelesene Meldungen aus angegebenen Quellen.

        Args:
            quellen: Iterable der Quellen-Filter.

        Returns:
            Anzahl ungelesener Meldungen, die nicht aufgeschoben sind.
        """
        ...

    @abstractmethod
    def zaehle_seit(self, quellen: Iterable[QuelleTyp], cutoff: datetime) -> int:
        """Zaehlt nicht-aufgeschobene Meldungen aus ``quellen`` seit ``cutoff``.

        Args:
            quellen: Iterable der Quellen-Filter.
            cutoff: Untere Zeitgrenze (UTC-aware).

        Returns:
            Anzahl passender Meldungen (INFO ausgeschlossen, Snooze beachtet).
        """
        ...


class ITechStackRepository(ABC):
    """Port für den persönlichen Tech-Stack."""

    @abstractmethod
    def lade(self) -> list[TechStackEintrag]:
        """Lädt den gespeicherten Tech-Stack.

        Returns:
            Liste der Tech-Stack-Einträge.
        """
        ...

    @abstractmethod
    def speichere(self, stack: list[TechStackEintrag]) -> None:
        """Speichert den kompletten Tech-Stack.

        Args:
            stack: Vollständige Liste der Einträge.
        """
        ...

    @abstractmethod
    def hinzufuegen(self, eintrag: TechStackEintrag) -> None:
        """Fügt einen Eintrag hinzu (keine Duplikate nach Name).

        Args:
            eintrag: Neuer Tech-Stack-Eintrag.
        """
        ...

    @abstractmethod
    def entfernen(self, name: str) -> None:
        """Entfernt einen Eintrag nach Name (case-insensitive).

        Args:
            name: Name des zu entfernenden Produkts.
        """
        ...
