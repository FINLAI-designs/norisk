"""
cisa_kev_client — CISA Known Exploited Vulnerabilities (KEV) Client.

Quelle: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
JSON-Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Kein API-Key noetig. Enthaelt ausschliesslich aktiv ausgenutzte Schwachstellen.
Die gesamte KEV-Liste wird als eine JSON-Datei (~2 MB) geladen und
clientseitig auf die letzten N Tage gefiltert.

Sicherheitsdesign:
  - get_http_client verwendet verify=True (SSL-Verifizierung erzwungen)
  - CVE-Inhalte werden nicht geloggt
  - Nur aggregierte Metadaten (Anzahl, Ladezeit) im Log

Schichtzugehoerigkeit: data/ — darf Domain-Modelle und core importieren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import requests

from core.http_client import get_http_client
from core.logger import get_logger
from tools.cyber_dashboard.domain.models import CveEintrag

_log = get_logger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_DAYS = 90


class CisaKevClient:
    """Laedt die CISA KEV-Liste und filtert auf aktuelle Eintraege.

    Die gesamte KEV-Liste wird als einzelne JSON-Datei geladen (~2 MB).
    Die Filterung auf die letzten N Tage erfolgt clientseitig.

    Alle zurueckgegebenen CveEintrag-Objekte haben ``cisa_kev=True``
    und ``schweregrad="HIGH"`` (alle KEVs sind aktiv ausgenutzt).
    """

    def __init__(self) -> None:
        """Initialisiert den Client mit dem zentralen HTTP-Client."""
        self._client = get_http_client()

    def fetch_recent_kevs(self, days: int = _DEFAULT_DAYS) -> list[CveEintrag]:
        """Holt die KEV-Liste und filtert auf die letzten N Tage.

        Laedt einmal den vollstaendigen KEV-Feed und gibt nur Eintraege
        zurueck deren ``dateAdded``-Datum innerhalb der letzten ``days``
        Tage liegt.

        Args:
            days: Nur KEVs die innerhalb der letzten N Tage hinzugefuegt
                  wurden. Standard: 90 Tage.

        Returns:
            CveEintrag-Objekte, neueste zuerst.
            Leere Liste bei Verbindungsfehler oder Parse-Fehler.
        """
        t0 = time.monotonic()
        try:
            response = self._client.get(_KEV_URL, timeout=20)
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            _log.error("CISA KEV Abruf fehlgeschlagen: %s", type(exc).__name__)
            return []

        vulnerabilities: list[dict] = data.get("vulnerabilities", [])
        cutoff = datetime.now(UTC) - timedelta(days=days)

        recent: list[CveEintrag] = []
        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                continue
            if added_dt < cutoff:
                continue
            recent.append(self._zu_cve_eintrag(vuln, added_dt))

        recent.sort(key=lambda c: c.veroeffentlicht, reverse=True)

        _log.info(
            "CISA KEV: %d aktuelle Eintraege (letzte %d Tage) von %d gesamt "
            "geladen in %.1fs",
            len(recent),
            days,
            len(vulnerabilities),
            time.monotonic() - t0,
        )
        return recent

    def _zu_cve_eintrag(self, vuln: dict, added_dt: datetime) -> CveEintrag:
        """Konvertiert einen KEV-Roheintrag in ein CveEintrag-Objekt.

        CISA KEV enthaelt keine CVSS-Scores. Alle KEV-Eintraege erhalten
        ``schweregrad="HIGH"`` und ``cvss_score=9.0`` als Platzhalter, da
        sie in freier Wildbahn aktiv ausgenutzt werden.

        Args:
            vuln: Roher KEV-Dict aus dem CISA JSON-Feed.
            added_dt: Bereits geparster dateAdded-Timestamp.

        Returns:
            CveEintrag mit cisa_kev=True.
        """
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")

        beschreibung = (
            vuln.get("shortDescription", "") or vuln.get("vulnerabilityName", "")
        )[:300]

        produkte: list[str] = []
        label = f"{vendor} {product}".strip()
        if label:
            produkte.append(label)

        return CveEintrag(
            cve_id=cve_id,
            beschreibung=beschreibung,
            schweregrad="HIGH",  # KEV = aktiv ausgenutzt — immer mindestens HIGH
            cvss_score=9.0,  # CISA KEV hat keine CVSS-Scores — Platzhalter
            veroeffentlicht=added_dt,
            geaendert=added_dt,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cisa_kev=True,
            cisa_frist=vuln.get("dueDate", ""),
            betroffene_produkte=produkte,
        )
