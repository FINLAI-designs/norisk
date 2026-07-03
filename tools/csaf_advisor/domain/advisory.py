"""
advisory — Domain-Entity für ein CSAF 2.0 Security Advisory.

Enthält nur reine Datenklassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CsafAdvisory:
    """Ein maschinenlesbares Security Advisory im CSAF 2.0 Format.

    Attributes:
        id: Eindeutiger Bezeichner (tracking_id + "_" + version).
        title: Advisory-Titel.
        publisher: Herausgeber (z. B. "BSI", "CISA", "Red Hat").
        tracking_id: CSAF tracking.id.
        tracking_version: Version des Advisory-Dokuments.
        initial_release: Erstveröffentlichung (ISO-Datum).
        current_release: Aktuellste Veröffentlichung (ISO-Datum).
        severity: Schweregrad: "critical", "high", "medium", "low".
        cvss_score: CVSS Base Score oder None wenn nicht vorhanden.
        cve_ids: Liste referenzierter CVE-Bezeichner.
        affected_products: Betroffene Produkte aus dem product_tree.
        summary: Zusammenfassung des Advisory.
        source_url: Original-URL des CSAF-Dokuments.
        raw_json: Originales CSAF JSON (komprimiert).
        fetched_at: ISO-Zeitstempel des letzten Abrufs.
    """

    id: str
    title: str
    publisher: str
    tracking_id: str
    tracking_version: str
    initial_release: str
    current_release: str
    severity: str
    cvss_score: float | None
    cve_ids: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    summary: str = ""
    source_url: str = ""
    raw_json: str = ""
    fetched_at: str = ""

    def severity_order(self) -> int:
        """Numerische Sortierreihenfolge nach Schweregrad (niedriger = kritischer).

        Returns:
            0 für critical, 1 für high, 2 für medium, 3 für low, 4 sonst.
        """
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return _order.get(self.severity.lower(), 4)
