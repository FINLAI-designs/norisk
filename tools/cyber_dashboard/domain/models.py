"""
models — Domänenmodelle für das Cyberrisiko-Dashboard.

Enthält alle Datenklassen und Enums für Cybersicherheits-Meldungen
und YouTube-Videos. Keine Außen-Abhängigkeiten (nur Python-Stdlib).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Schweregrad(Enum):
    """Schweregrad einer Cybersicherheits-Meldung."""

    KRITISCH = "kritisch"
    HOCH = "hoch"
    MITTEL = "mittel"
    NIEDRIG = "niedrig"
    INFO = "info"


class QuelleTyp(Enum):
    """Typ der Informationsquelle."""

    CERT_AT = "CERT.at"
    BSI = "BSI CERT-Bund"
    ENISA = "ENISA"  # Nicht mehr aktiv geladen — DB-Kompatibilitaet
    CERT_EU = "CERT-EU"  # Nicht mehr aktiv geladen — DB-Kompatibilitaet
    CVE_FEED = "CVEfeed"  # Nicht mehr aktiv geladen — DB-Kompatibilitaet
    YOUTUBE = "SimplyCyber"
    THE_HACKER_NEWS = "The Hacker News"  # Neu: ersetzt ENISA/CERT-EU/CVEfeed
    # 2026-05-14: Watchlist Internet (OIAT) — oesterreichischer Standard
    # fuer Phishing-/Betrugs-Warnungen, taegliche Updates, RSS 2.0 mit
    # category-Tags (Phishing, Abo-Fallen, Finanzbetrug,...).
    WATCHLIST_AT = "Watchlist Internet"
    # 2026-05-28 — Phishing-Radar-Refactor: Tier 1 DACH
    # (siehe Plan ``sehr-gute-recherche-bevor-cozy-fiddle.md``).
    MIMIKAMA = "Mimikama"
    VZ_DIGITAL = "Verbraucherzentrale Digital"
    NCSC_CH = "NCSC Schweiz"
    POLIZEI_NDS = "Polizei-Prävention NDS"
    HEISE_SECURITY = "heise Security Alerts"
    # 2026-05-28 — Phishing-Radar-Refactor: Tier 2 international
    ESET_WLS_DE = "ESET WeLiveSecurity DE"
    MALWAREBYTES_LABS = "Malwarebytes Labs"
    KREBS = "Krebs on Security"
    BLEEPING = "BleepingComputer"
    NCSC_UK = "NCSC UK"
    SANS_ISC = "SANS ISC Diary"


class Kategorie(Enum):
    """Inhaltliche Kategorie einer Quelle.

    Trennt Konsumenten-Phishing-Alerts (Watchlist, Mimikama, …) von
    Awareness-Stories (Krebs, Malwarebytes), allgemeinen Security-Alerts
    (heise, NCSC UK) und technischen CVE-Feeds (CERT-AT, BSI, THN).
    Banner und Inbox-Modal filtern darüber, das Cyber-Dashboard zeigt
    weiterhin alle Quellen via ``lade_meldungen``.
    """

    PHISHING_CONSUMER = "phishing_consumer"
    PHISHING_AWARENESS = "phishing_awareness"
    SECURITY_ALERT = "security_alert"
    TECH_CVE = "tech_cve"


QUELLE_KATEGORIE: dict[QuelleTyp, Kategorie] = {
    # Phishing-Konsumenten — laienverstaendliche Warnungen, DACH-Sprachraum.
    QuelleTyp.WATCHLIST_AT: Kategorie.PHISHING_CONSUMER,
    QuelleTyp.MIMIKAMA: Kategorie.PHISHING_CONSUMER,
    QuelleTyp.VZ_DIGITAL: Kategorie.PHISHING_CONSUMER,
    QuelleTyp.NCSC_CH: Kategorie.PHISHING_CONSUMER,
    QuelleTyp.POLIZEI_NDS: Kategorie.PHISHING_CONSUMER,
    # Phishing-Awareness — internationale Storytelling-/Vendor-Blogs.
    QuelleTyp.ESET_WLS_DE: Kategorie.PHISHING_AWARENESS,
    QuelleTyp.MALWAREBYTES_LABS: Kategorie.PHISHING_AWARENESS,
    QuelleTyp.KREBS: Kategorie.PHISHING_AWARENESS,
    QuelleTyp.BLEEPING: Kategorie.PHISHING_AWARENESS,
    # Allgemeine Security-Alerts — Schwachstellen, Incidents.
    QuelleTyp.HEISE_SECURITY: Kategorie.SECURITY_ALERT,
    QuelleTyp.NCSC_UK: Kategorie.SECURITY_ALERT,
    QuelleTyp.SANS_ISC: Kategorie.SECURITY_ALERT,
    # Technische CVE-Feeds — bleiben dem Cyber-Dashboard vorbehalten.
    QuelleTyp.CERT_AT: Kategorie.TECH_CVE,
    QuelleTyp.BSI: Kategorie.TECH_CVE,
    QuelleTyp.THE_HACKER_NEWS: Kategorie.TECH_CVE,
}


def kategorie_fuer(quelle: QuelleTyp) -> Kategorie | None:
    """Hilfsfunktion: Kategorie zu einer Quelle.

    Returns ``None`` fuer historische Quellen (ENISA, CERT_EU, CVE_FEED,
    YOUTUBE), die in der ``QUELLE_KATEGORIE``-Map nicht enthalten sind.
    """

    return QUELLE_KATEGORIE.get(quelle)


def quellen_fuer_kategorien(
    kategorien: Iterable[Kategorie],
) -> list[QuelleTyp]:
    """Liefert alle Quellen, die zu einer der ``kategorien`` gehoeren.

    Zentrale Ableitung Kategorie -> Quellen — Single Source of Truth fuer
    Service-Filter und GUI-Quellenliste, damit die Map nicht an mehreren
    Stellen reimplementiert wird.

    Args:
        kategorien: Iterable von Kategorie-Werten.

    Returns:
        Liste der zugehoerigen ``QuelleTyp``-Werte (Reihenfolge wie in
        ``QUELLE_KATEGORIE``).
    """

    kategorien_set = set(kategorien)
    return [q for q, k in QUELLE_KATEGORIE.items() if k in kategorien_set]


@dataclass(frozen=True)
class CyberMeldung:
    """Eine Cybersicherheits-Meldung aus einem RSS-Feed.

    Attributes:
        titel: Überschrift der Meldung.
        beschreibung: Kurzbeschreibung (max. 300 Zeichen).
        url: Direktlink zur vollständigen Meldung.
        quelle: Herkunft der Meldung.
        schweregrad: Eingeschätzter Schweregrad.
        veroeffentlicht: Veröffentlichungszeitpunkt (UTC).
        guid: Eindeutiger Bezeichner — Standard: url.
    """

    titel: str
    beschreibung: str
    url: str
    quelle: QuelleTyp
    schweregrad: Schweregrad
    veroeffentlicht: datetime
    guid: str = field(default="")

    def __post_init__(self) -> None:
        if not self.guid:
            object.__setattr__(self, "guid", self.url)


@dataclass(frozen=True)
class YouTubeVideo:
    """Ein YouTube-Video aus dem SimplyCyber RSS-Feed.

    Attributes:
        video_id: YouTube Video-ID (11 Zeichen).
        titel: Videotitel.
        beschreibung: Kurzbeschreibung (max. 200 Zeichen).
        url: YouTube-Watchlink.
        veroeffentlicht: Veröffentlichungsdatum.
        thumbnail_url: URL des Vorschaubilds (optional).
    """

    video_id: str
    titel: str
    beschreibung: str
    url: str
    veroeffentlicht: datetime
    thumbnail_url: str = field(default="")

    @property
    def embed_url(self) -> str:
        """YouTube-Embed-URL für die Einbettung im WebEngine-View.

        Verwendet youtube-nocookie.com (datenschutzfreundlich, keine
        Tracking-Cookies). Gibt leeren String zurück wenn die video_id
        ungültig ist (nur alphanumerisch + _ + - erlaubt, max. 12 Zeichen).

        Returns:
            Vollständige Embed-URL oder leer bei ungültiger video_id.
        """
        allowed = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        )
        if not self.video_id or len(self.video_id) > 12:
            return ""
        if not all(c in allowed for c in self.video_id):
            return ""
        return (
            f"https://www.youtube-nocookie.com/embed/{self.video_id}"
            f"?rel=0&modestbranding=1&autoplay=0"
        )


@dataclass(frozen=True)
class CveEintrag:
    """Ein CVE-Eintrag aus der NVD API 2.0.

    Attributes:
        cve_id: CVE-Identifikator (z.B. CVE-2024-1234).
        beschreibung: Englische Beschreibung (max. 300 Zeichen).
        schweregrad: CRITICAL/HIGH/MEDIUM/LOW/INFO.
        cvss_score: Numerischer CVSS-Score (0.0–10.0).
        veroeffentlicht: Veröffentlichungsdatum (UTC).
        geaendert: Letztes Änderungsdatum (UTC).
        url: Direktlink zum NVD-Eintrag.
        patch_verfuegbar: True wenn ein Patch bekannt ist.
        cisa_kev: True wenn CVE in CISA KEV-Liste (aktiv ausgenutzt).
        cisa_frist: CISA-Aktionsfrist als ISO-Datum oder leer.
        betroffene_produkte: Liste betroffener Produkte (max. 3).
    """

    cve_id: str
    beschreibung: str
    schweregrad: str
    cvss_score: float
    veroeffentlicht: datetime
    geaendert: datetime
    url: str
    patch_verfuegbar: bool = False
    cisa_kev: bool = False
    cisa_frist: str = ""
    betroffene_produkte: list[str] = field(default_factory=list)

    @property
    def nvd_url(self) -> str:
        """Direktlink zur NVD-Detailseite.

        Returns:
            Vollständige NVD-URL.
        """
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


class ConsumerQuelle(Enum):
    """Typ der Consumer-Software-Security-Quelle (BSI-Bürger, MSRC, Chrome, Mozilla)."""

    BSI = "BSI"
    MSRC = "MSRC"
    CHROME = "Chrome"
    MOZILLA = "Mozilla"


@dataclass(frozen=True)
class ConsumerMeldung:
    """Sicherheits-Meldung zu verbreiteter Consumer-Software.

    Wird parallel zu ``CyberMeldung`` gehalten, weil die Kategorisierung
    und Badge-Logik im Briefing eine eigene Sektion bedient.

    Attributes:
        titel: Überschrift der Meldung.
        beschreibung: Kurzbeschreibung (max. 300 Zeichen).
        url: Direktlink zur vollständigen Meldung.
        quelle: Herkunft (BSI / MSRC / Chrome / Mozilla).
        veroeffentlicht: Veröffentlichungszeitpunkt.
        produkt: Produkt-Name (z.B. "Windows 11", "Chrome 123").
        schweregrad: Optionaler Schweregrad (falls im Feed vorhanden).
        guid: Eindeutiger Bezeichner — Standard: url.
    """

    titel: str
    beschreibung: str
    url: str
    quelle: ConsumerQuelle
    veroeffentlicht: datetime
    produkt: str = ""
    schweregrad: Schweregrad | None = None
    guid: str = field(default="")

    def __post_init__(self) -> None:
        if not self.guid:
            object.__setattr__(self, "guid", self.url)


@dataclass(frozen=True)
class TechStackEintrag:
    """Ein Produkt im persönlichen Tech-Stack für CVE-Monitoring.

    Attributes:
        name: Produktname (z.B. "Windows", "Python").
        version: Optionale Versionsnummer (z.B. "Server 2022").
        kategorie: Produktkategorie (OS/App/Library/Runtime/Datenbank).
        aktiv: True wenn dieser Eintrag beim CVE-Scan berücksichtigt wird.
        cpe: Optionaler Common-Platform-Enumeration-String (z.B.
            ``cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*``). Wird beim Sync
            aus dem Patch-Monitor übernommen und ermöglicht ein
            präzises CVE-Matching über die lokal gematchten CVEs des
            Patch-Monitors — auch ohne NVD-API-Key. Leer für manuell
            angelegte Einträge und Alt-Bestand (back-compat).
    """

    name: str
    version: str = ""
    kategorie: str = ""
    aktiv: bool = True
    cpe: str = ""


@dataclass(frozen=True)
class TechStackKandidat:
    """Ein beim Sync erkanntes Produkt als Übernahme-Vorschlag.

    Bündelt den abgeleiteten:class:`TechStackEintrag` mit der Information,
    aus welcher Quelle (System-Scan und/oder Patch-Monitor) er stammt —
    die GUI zeigt das im Vorschau-Dialog zur Kuratierung an.

    Attributes:
        eintrag: Der vorgeschlagene Tech-Stack-Eintrag (inkl. ``cpe``).
        quellen: Anzeige-Labels der Herkunftsquellen (z.B. ``("System-Scan",
            "Patch-Monitor")`` bei einem Treffer in beiden).
    """

    eintrag: TechStackEintrag
    quellen: tuple[str, ...] = ()
