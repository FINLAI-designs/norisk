"""curated_links — Fest kuratierte Wichtige Links pro App.

Kuratierte Links werden NICHT in der Datenbank gespeichert — sie stammen
direkt aus diesem Modul und können per App-Update aktualisiert werden.
Nur User-eigene Links werden in der EncryptedDatabase (LinksRepository) abgelegt.

Schichtzugehörigkeit: core/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CuratedLink:
    """Ein kuratierter, nicht löschbarer Wichtiger Link.

    Attributes:
        title: Anzeigename in Sidebar und Einstellungen.
        url: Vollständige URL inkl. Schema.
        category: Gruppierungsbegriff (z.B. "Offizielle Ressourcen").
        icon: Material Symbol Name (z.B. "shield", "database").
        description: Kurzbeschreibung (optional, für Tooltip).
        sort_order: Sortierreihenfolge (aufsteigend, global innerhalb der App).
    """

    title: str
    url: str
    category: str
    icon: str = "link"
    description: str = ""
    sort_order: int = 0


# ---------------------------------------------------------------------------
# NoRisk — Cybersecurity
# ---------------------------------------------------------------------------

NORISK_CURATED_LINKS: list[CuratedLink] = [
    # 2026-06-25: Liste bewusst auf je EINE Leitquelle pro Bereich verschlankt
    # (Patrick-Entscheid Live-Test) — vorher 10 Links, wirkte ueberladen.
    # === BSI & Deutschland ============================================
    CuratedLink(
        title="BSI — Startseite",
        url="https://www.bsi.bund.de/",
        category="BSI & Deutschland",
        icon="shield",
        description="Bundesamt für Sicherheit in der Informationstechnik — zentrale Ressourcen für KMU",
        sort_order=1,
    ),
    # === Österreich ===================================================
    # URL gegengeprüft 2026-06-26 (Patrick): die offizielle Stelle ist
    # ncc.GV.at (Nationales Koordinierungszentrum Cybersicherheit, NCC-AT) —
    # ncc.at ohne.gv ist ein geparkter Server (Default-TLS-Cert your-server.de).
    # 564ee75 hatte versehentlich.gv entfernt -> hier wiederhergestellt.
    CuratedLink(
        title="NCSC Austria",
        url="https://www.ncc.gv.at/",
        category="Österreich",
        icon="flag",
        description="Nationales Koordinierungszentrum Cybersicherheit (NCC-AT) — offizielle nationale Stelle",
        sort_order=10,
    ),
    # === Schwachstellen-Datenbanken ===================================
    CuratedLink(
        title="NVD — National Vulnerability Database",
        url="https://nvd.nist.gov/",
        category="Schwachstellen-Datenbanken",
        icon="database",
        description="NIST-Schwachstellendatenbank — CVE-Einträge mit CVSS-Bewertungen",
        sort_order=20,
    ),
]

# ---------------------------------------------------------------------------
# FINLAI — Finance & Accounting Intelligence
# ---------------------------------------------------------------------------

FINLAI_CURATED_LINKS: list[CuratedLink] = [
    # Platzhalter — später mit Finance/TaxTech-spezifischen Links befüllen:
    # z.B. Bundesfinanzministerium, FinanzOnline, WKO Steuerinfo, ELSTER etc.
]

# ---------------------------------------------------------------------------
# AUTOMATE — TaxTech-Automatisierung
# ---------------------------------------------------------------------------

AUTOMATE_CURATED_LINKS: list[CuratedLink] = [
    # Platzhalter — später mit Automatisierungs-/SFTP-spezifischen Links befüllen
]

# ---------------------------------------------------------------------------
# TeachMe — Programmier-Dokumentationen und Lernressourcen
# ---------------------------------------------------------------------------

TEACHME_CURATED_LINKS: list[CuratedLink] = [
    # === Offizielle Dokumentationen ===
    CuratedLink(
        title="Python Docs",
        url="https://docs.python.org",
        category="docs",
        icon="description",
        description="Offizielle Python 3 Dokumentation",
        sort_order=1,
    ),
    CuratedLink(
        title="MDN Web Docs",
        url="https://developer.mozilla.org",
        category="docs",
        icon="public",
        description="Mozilla Developer Network — JS, CSS, HTML",
        sort_order=2,
    ),
    CuratedLink(
        title="PHP Manual",
        url="https://www.php.net/manual",
        category="docs",
        icon="description",
        description="Offizielle PHP Dokumentation",
        sort_order=3,
    ),
    CuratedLink(
        title="MySQL Docs",
        url="https://dev.mysql.com/doc",
        category="docs",
        icon="storage",
        description="MySQL Referenz-Handbuch",
        sort_order=4,
    ),
    CuratedLink(
        title="MS Learn — VBA",
        url="https://learn.microsoft.com/office/vba",
        category="docs",
        icon="school",
        description="VBA Referenz für Office",
        sort_order=5,
    ),
    # === Lernplattformen ===
    CuratedLink(
        title="W3Schools",
        url="https://www.w3schools.com",
        category="learn",
        icon="school",
        description="Interaktive Tutorials für Web-Technologien",
        sort_order=10,
    ),
    CuratedLink(
        title="Real Python",
        url="https://realpython.com",
        category="learn",
        icon="code",
        description="Python Tutorials und Deep Dives",
        sort_order=11,
    ),
    CuratedLink(
        title="freeCodeCamp",
        url="https://www.freecodecamp.org",
        category="learn",
        icon="school",
        description="Kostenlose Programmierkurse mit Zertifikaten",
        sort_order=12,
    ),
    CuratedLink(
        title="JavaScript.info",
        url="https://javascript.info",
        category="learn",
        icon="javascript",
        description="Modernes JavaScript Tutorial",
        sort_order=13,
    ),
    CuratedLink(
        title="CSS-Tricks",
        url="https://css-tricks.com",
        category="learn",
        icon="brush",
        description="CSS Guides, Tricks und Almanac",
        sort_order=14,
    ),
    CuratedLink(
        title="SQLZoo",
        url="https://sqlzoo.net",
        category="learn",
        icon="storage",
        description="Interaktive SQL-Übungen",
        sort_order=15,
    ),
    # === Referenzen ===
    CuratedLink(
        title="DevDocs",
        url="https://devdocs.io",
        category="reference",
        icon="menu_book",
        description="Alle Dokumentationen an einem Ort",
        sort_order=20,
    ),
    CuratedLink(
        title="Refactoring Guru",
        url="https://refactoring.guru",
        category="reference",
        icon="architecture",
        description="Design Patterns und Refactoring erklärt",
        sort_order=21,
    ),
    CuratedLink(
        title="Can I Use",
        url="https://caniuse.com",
        category="reference",
        icon="devices",
        description="Browser-Kompatibilität für CSS/JS Features",
        sort_order=22,
    ),
    CuratedLink(
        title="Regex101",
        url="https://regex101.com",
        category="reference",
        icon="manage_search",
        description="RegEx testen und debuggen",
        sort_order=23,
    ),
    CuratedLink(
        title="Big-O Cheat Sheet",
        url="https://www.bigocheatsheet.com",
        category="reference",
        icon="speed",
        description="Algorithmen-Komplexität auf einen Blick",
        sort_order=24,
    ),
    # === Community ===
    CuratedLink(
        title="Stack Overflow",
        url="https://stackoverflow.com",
        category="community",
        icon="forum",
        description="Fragen und Antworten zu Programmierung",
        sort_order=30,
    ),
    CuratedLink(
        title="GitHub",
        url="https://github.com",
        category="community",
        icon="code",
        description="Code-Hosting und Open-Source-Projekte",
        sort_order=31,
    ),
    CuratedLink(
        title="GitHub Docs",
        url="https://docs.github.com",
        category="community",
        icon="menu_book",
        description="Git und GitHub Dokumentation",
        sort_order=32,
    ),
    CuratedLink(
        title="Reddit r/learnprogramming",
        url="https://www.reddit.com/r/learnprogramming",
        category="community",
        icon="forum",
        description="Community für Programmier-Einsteiger",
        sort_order=33,
    ),
]

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_CURATED: dict[str, list[CuratedLink]] = {
    "norisk": NORISK_CURATED_LINKS,
    "finlai": FINLAI_CURATED_LINKS,
    "automate": AUTOMATE_CURATED_LINKS,
    "teachme": TEACHME_CURATED_LINKS,
}


def get_curated_links(app_id: str) -> list[CuratedLink]:
    """Gibt die kuratierten Links für eine App zurück, sortiert nach sort_order.

    Args:
        app_id: App-Kennung (``"norisk"``, ``"finlai"``, ``"automate"``).

    Returns:
        Nach sort_order sortierte Liste der CuratedLink-Objekte.
        Leere Liste wenn app_id unbekannt.
    """
    return sorted(_CURATED.get(app_id, []), key=lambda lnk: lnk.sort_order)
