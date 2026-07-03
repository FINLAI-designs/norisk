"""
csaf_to_cve_adapter — Konvertiert CSAF-Advisories in CveEintrag.

Brückt das ``csaf_advisor``-Tool ins ``cyber_dashboard``: persistierte
BSI-WID- und Hersteller-Advisories werden in ``CveEintrag`` übersetzt
und landen über ``CacheRepository.speichere_cves`` in der gleichen
``cves``-Tabelle wie CISA KEV und NVD-Daten.

Effekt im CVE-Tab: echte CVSS-Scores, ``CRITICAL``/``HIGH``/``MEDIUM``/
``LOW``-Severities (statt KEV-pauschal-HIGH-9.0) und EU-Hersteller-
Bezug (SEPPmail, SAP, Siemens,...) — nicht nur USA-NVD-Fokus.

Schichtzugehörigkeit: ``application/`` — darf andere Tools über deren
``application/``-Layer lesen (Cross-Tool-Read ist erlaubt; ``data/``-
Imports laufen über die csaf_advisor-Factory).

Author: Patrick Riederich
Version: 1.0 follow-up, 2026-05-14)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from core.logger import get_logger
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.cyber_dashboard.domain.models import CveEintrag

log = get_logger(__name__)

# Konsistent mit NVD-Parser (``nvd_service._parse_cve``): nur die ersten
# 3 betroffenen Produkte landen im CVE-Eintrag — die Tabelle hat keine
# vernünftige Anzeige für lange Produktlisten.
#
# Konsequenz für Stack-Match (siehe ``DashboardService._filtere_nach_stack``):
# Wenn ein CSAF-Advisory 10 Produkte betrifft, nur die ersten 3 nutzen,
# erhöht das die Chance dass ein Match übersehen wird. Bewusster
# Trade-off zugunsten konsistenter UI; Korrektheits-Review P3-Befund.
_MAX_AFFECTED_PRODUCTS = 3

# CSAF-Severity (lowercase) → CveEintrag-Schweregrad (uppercase, NVD-konform).
_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

# Wenn ein Advisory korruptes/leeres ``current_release`` hat, sortieren
# wir den Eintrag ans Ende statt versehentlich oben anzuzeigen
# (Korrektheits-Review P1).
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Synthetische CSAF-IDs: alles außer Buchstaben/Ziffern/.-_ wird ersetzt
# (Hersteller-IDs koennen Sonderzeichen enthalten, siehe Review P2).
_TRACKING_ID_SAFE = re.compile(r"[^A-Za-z0-9._-]")

# Cap auf Synthetische CSAF-IDs — Schutz gegen DB-Bloat / UI-Verzerrung
# bei bösartigem Provider (Security-Review P2).
_MAX_SYNTHETIC_ID_LEN = 64

# Einzelne ``affected_products``-Strings cappen — ein 1-MB-Produktname
# wuerde sonst via ``json.dumps`` ungebremst in die SQLCipher-DB
# wandern. Security-Review P2.
_MAX_PRODUCT_NAME_LEN = 200


def csaf_advisories_to_cves(
    advisories: list[CsafAdvisory],
) -> list[CveEintrag]:
    """Konvertiert eine Liste CSAF-Advisories in flache ``CveEintrag``-Liste.

    Pro Advisory wird **ein** ``CveEintrag`` pro referenzierter CVE-ID
    erzeugt; Advisories ohne ``cve_ids`` bekommen einen synthetischen
    Eintrag mit ``CSAF-{tracking_id}`` als CVE-ID (damit der Eintrag im
    CVE-Tab trotzdem sichtbar wird).

    Mapping-Regeln:
      * ``severity`` (lower) → ``schweregrad`` (UPPER). Unbekannt → ``INFO``.
      * ``cvss_score`` → ``cvss_score`` (None → 0.0).
      * ``current_release`` (ISO-String) → ``veroeffentlicht`` + ``geaendert``.
      * ``source_url`` → ``url`` (Original-CSAF-Dokument).
      * ``cisa_kev=False`` — CSAF und KEV sind unabhängige Quellen.
      * ``betroffene_produkte`` cappt auf 3.

    Args:
        advisories: CSAF-Advisories aus dem ``csaf_advisor``-Repository.

    Returns:
        Liste konvertierter ``CveEintrag``-Objekte. Leer wenn ``advisories``
        leer ist.
    """
    if not advisories:
        return []

    # Dict statt Liste: bei Cross-Advisory-Duplikaten (BSI-WID +
    # Hersteller-Advisory referenzieren dieselbe CVE-ID) gewinnt der
    # höhere CVSS-Score. SQLite würde sonst den letzten Eintrag in der
    # Liste behalten (INSERT OR REPLACE — willkürliche Reihenfolge).
    # Korrektheits-Review P2.
    by_cve_id: dict[str, CveEintrag] = {}
    for adv in advisories:
        schweregrad = _SEVERITY_MAP.get(adv.severity.lower(), "INFO")
        cvss = float(adv.cvss_score) if adv.cvss_score is not None else 0.0
        produkte = list(adv.affected_products[:_MAX_AFFECTED_PRODUCTS])
        release_dt = _parse_release(adv.current_release)
        summary = (adv.summary or adv.title or "")[:300]

        cve_ids = list(adv.cve_ids) if adv.cve_ids else [_synthetic_cve_id(adv)]
        # Einzel-Produkt-Strings kappen — Schutz gegen DB-Bloat
        # (Security-Review P2).
        produkte_capped = [p[:_MAX_PRODUCT_NAME_LEN] for p in produkte]

        for cve_id in cve_ids:
            candidate = CveEintrag(
                cve_id=cve_id,
                beschreibung=summary,
                schweregrad=schweregrad,
                cvss_score=cvss,
                veroeffentlicht=release_dt,
                geaendert=release_dt,
                url=adv.source_url,
                cisa_kev=False,
                cisa_frist="",
                betroffene_produkte=produkte_capped,
            )
            existing = by_cve_id.get(cve_id)
            if existing is None or candidate.cvss_score > existing.cvss_score:
                by_cve_id[cve_id] = candidate

    return list(by_cve_id.values())


def _synthetic_cve_id(adv: CsafAdvisory) -> str:
    """Baut eine sanitisierte synthetische CSAF-ID.

    Hersteller-Advisories ohne CVE-Referenz brauchen einen eindeutigen
    Primary Key in der `cves`-Tabelle. ``tracking_id`` kann Slashes,
    Spaces oder Unicode enthalten — wir ersetzen alles außer
    ``[A-Za-z0-9._-]`` durch ``_`` und cappen auf
    ``_MAX_SYNTHETIC_ID_LEN`` (Schutz gegen DB-Bloat bei bösartigem
    Provider). Vgl. Korrektheits-Review P2 + Security-Review P2.
    """
    safe = _TRACKING_ID_SAFE.sub("_", adv.tracking_id or "unknown")
    return f"CSAF-{safe[:_MAX_SYNTHETIC_ID_LEN]}"


def _parse_release(release: str) -> datetime:
    """Parst ``current_release`` (CSAF ISO-Datetime mit oder ohne ``Z``).

    Fallback bei korruptem/leerem Wert: ``_EPOCH`` (1970-01-01 UTC) —
    der Eintrag landet am Ende der ``veroeffentlicht DESC``-Sortierung
    statt versehentlich oben (Korrektheits-Review P1).
    """
    try:
        dt = datetime.fromisoformat(release.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except (ValueError, AttributeError, TypeError):
        log.warning(
            "CSAF-current_release unparsbar — sortiere ans Ende (%r)",
            release,
        )
        return _EPOCH


__all__ = ["csaf_advisories_to_cves"]
