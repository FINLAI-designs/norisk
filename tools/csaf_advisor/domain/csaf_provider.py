"""
csaf_provider — Domain-Entity für einen CSAF Trusted Provider.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CsafProvider:
    """Ein CSAF 2.0 Trusted Provider (Quelle für Security Advisories).

    Attributes:
        id: Eindeutiger Bezeichner (z. B. "csaf-bsi").
        name: Anzeigename (z. B. "BSI (Deutschland)").
        provider_url: URL zur provider-metadata.json.
        feed_url: URL zum ROLIE-Feed oder index.txt (kann leer sein).
        source: "curated" (vordefiniert) oder "user" (selbst angelegt).
        enabled: True wenn dieser Provider beim Abruf berücksichtigt wird.
        last_fetch: ISO-Zeitstempel des letzten erfolgreichen Abrufs.
        advisory_count: Anzahl der zuletzt geladenen Advisories.
    """

    id: str
    name: str
    provider_url: str
    feed_url: str = ""
    source: str = "user"
    enabled: bool = True
    last_fetch: str = ""
    advisory_count: int = 0

    @property
    def is_curated(self) -> bool:
        """True wenn der Provider vom FINLAI-Team vordefiniert wurde.

        Returns:
            True wenn source == "curated".
        """
        return self.source == "curated"
