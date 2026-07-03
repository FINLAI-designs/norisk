"""
cve_exposure_repository — Read-Only-Adapter für die CVE-Exposure-Aggregation.

Liest:
  - gecachte NVD/KEV-CVEs aus ``cyber_dashboard``-SQLCipher-DB
    (CacheRepository.lade_cves — kein NVD-Request)
  - CSAF-Advisory-Matches aus ``csaf_advisor``-SQLCipher-DB
    (AdvisoryRepository.list_matches + get_advisory — kein Feed-Download)
  - das eigene System-Profil inkl. Tech-Stack aus ``security_scoring``-DB
    (TechStackRepository.get_own_system)

CVEs werden auf Produkte des aktiven Tech-Stacks gefiltert
(case-insensitive Substring-Match in beiden Richtungen).

Schichtzugehörigkeit: data/ — keine GUI-Imports, kein Netzwerk-I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.logger import get_logger

if TYPE_CHECKING:
    from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
    from tools.cyber_dashboard.domain.models import CveEintrag

log = get_logger(__name__)

_MAX_CACHE_CVES: int = 500
_MIN_TOKEN_LEN: int = 3


class CveExposureRepository:
    """Aggregiert Read-Only-Zugriffe auf drei bestehende Repositories.

    Dependency-Injection für Tests (Mock-Repositories übergeben) oder
    produktive Nutzung mit Default-Instanzen.

    Attributes:
        _cache_repo: CacheRepository (cyber_dashboard-DB).
        _advisory_repo: AdvisoryRepository (csaf_advisor-DB).
        _tech_stack_repo: TechStackRepository (security_scoring-DB).
    """

    def __init__(
        self,
        cache_repo=None,
        advisory_repo=None,
        tech_stack_repo=None,
    ) -> None:
        """Initialisiert das Repository mit den drei Quellen.

        Fehlt ein Parameter, wird die Standard-Repository-Klasse konstruiert.
        Import erst im Konstruktor, um zirkuläre Imports zu vermeiden.

        Args:
            cache_repo: CacheRepository-Instanz oder None (Standard:
                             ``tools.cyber_dashboard.data.cache_repository.CacheRepository``).
            advisory_repo: AdvisoryRepository-Instanz oder None (Standard:
                             ``tools.csaf_advisor.data.advisory_repository_impl.AdvisoryRepository``).
            tech_stack_repo: TechStackRepository-Instanz oder None (Standard:
                             ``tools.security_scoring.data.tech_stack_repository.TechStackRepository``).
        """
        if cache_repo is None:
            from tools.cyber_dashboard.data.cache_repository import (  # noqa: PLC0415
                CacheRepository,
            )

            cache_repo = CacheRepository()
        if advisory_repo is None:
            from tools.csaf_advisor.data.advisory_repository_impl import (  # noqa: PLC0415
                AdvisoryRepository,
            )

            advisory_repo = AdvisoryRepository()
        if tech_stack_repo is None:
            from tools.security_scoring.data.tech_stack_repository import (  # noqa: PLC0415
                TechStackRepository,
            )

            tech_stack_repo = TechStackRepository()

        self._cache_repo = cache_repo
        self._advisory_repo = advisory_repo
        self._tech_stack_repo = tech_stack_repo

    # ------------------------------------------------------------------
    # Öffentliche API
    # ------------------------------------------------------------------

    def lade_techstack_cves(self) -> list[CveEintrag]:
        """Lädt alle gecachten CVEs die Produkte aus dem Tech-Stack betreffen.

        Produkt-Matching: case-insensitive Substring-Vergleich zwischen
        Tech-Stack-Produktnamen und CveEintrag.betroffene_produkte.
        Token < ``_MIN_TOKEN_LEN`` Zeichen werden ignoriert.

        Returns:
            Liste der passenden CveEintrag-Objekte. Leer wenn Tech-Stack
            keine Produkte enthält oder der Cache leer ist.
        """
        produktnamen = self._aktive_techstack_produkte()
        if not produktnamen:
            return []

        try:
            alle_cves = self._cache_repo.lade_cves(limit=_MAX_CACHE_CVES)
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning("Cache-Zugriff fehlgeschlagen: %s", type(exc).__name__)
            return []

        return [cve for cve in alle_cves if self._cve_matcht_stack(cve, produktnamen)]

    def zaehle_betroffene_advisories(self) -> int:
        """Zählt Advisory-Matches mit Severity 'critical' oder 'high'.

        Lädt alle Matches und das zugehörige Advisory-Inventar in einem
        Schritt (dict-Lookup, kein N+1). Severity wird lower-case verglichen.

        Returns:
            Anzahl der Matches deren Advisory Severity critical oder high hat.
        """
        try:
            matches: list[AdvisoryMatch] = self._advisory_repo.list_matches()
            if not matches:
                return 0
            advisories = self._advisory_repo.list_advisories()
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "CSAF-Match-Zugriff fehlgeschlagen: %s", type(exc).__name__
            )
            return 0

        severity_by_id = {a.id: (a.severity or "").lower() for a in advisories}
        return sum(
            1
            for m in matches
            if severity_by_id.get(m.advisory_id) in ("critical", "high")
        )

    def letzte_aktualisierung(self) -> str:
        """Ermittelt den jüngsten Zeitstempel aus CVE- und Advisory-Quelle.

        Returns:
            ISO-Timestamp (string) oder leerer String wenn beide Quellen leer.
        """
        kandidaten: list[str] = []

        try:
            cves = self._cache_repo.lade_cves(limit=_MAX_CACHE_CVES)
            for cve in cves:
                geaendert = getattr(cve, "geaendert", None)
                if geaendert is None:
                    continue
                iso = (
                    geaendert.isoformat()
                    if hasattr(geaendert, "isoformat")
                    else str(geaendert)
                )
                if iso:
                    kandidaten.append(iso)
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning("CVE-Timestamp-Lesen fehlgeschlagen: %s", type(exc).__name__)

        try:
            matches = self._advisory_repo.list_matches()
            for m in matches:
                if m.matched_at:
                    kandidaten.append(m.matched_at)
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "Match-Timestamp-Lesen fehlgeschlagen: %s", type(exc).__name__
            )

        return max(kandidaten) if kandidaten else ""

    # ------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ------------------------------------------------------------------

    def _aktive_techstack_produkte(self) -> list[str]:
        """Extrahiert Produktnamen des eigenen Systems für das CVE-Matching.

        Berücksichtigt OS, Browser, Antivirus, Firewall, VPN,
        remote_access und custom_software. Leere Strings werden gefiltert.

        Returns:
            Liste eindeutiger Produktnamen (Original-Schreibweise).
        """
        try:
            profile = self._tech_stack_repo.get_own_system()
        except (OSError, RuntimeError, AttributeError) as exc:
            log.warning(
                "Tech-Stack-Zugriff fehlgeschlagen: %s", type(exc).__name__
            )
            return []

        if profile is None or profile.tech_stack is None:
            return []

        stack = profile.tech_stack
        rohwerte: list[str] = []
        rohwerte.extend(os_entry.name for os_entry in stack.operating_systems)
        rohwerte.extend(browser.name for browser in stack.browsers)
        if stack.antivirus and stack.antivirus.name:
            rohwerte.append(stack.antivirus.name)
        if stack.firewall and stack.firewall.name:
            rohwerte.append(stack.firewall.name)
        if stack.vpn:
            rohwerte.append(stack.vpn)
        rohwerte.extend(stack.remote_access)
        rohwerte.extend(stack.custom_software)

        bereinigt = []
        gesehen: set[str] = set()
        for rohwert in rohwerte:
            name = (rohwert or "").strip()
            if len(name) < _MIN_TOKEN_LEN:
                continue
            schluessel = name.lower()
            if schluessel in gesehen:
                continue
            gesehen.add(schluessel)
            bereinigt.append(name)
        return bereinigt

    @staticmethod
    def _cve_matcht_stack(cve: CveEintrag, produktnamen: list[str]) -> bool:
        """Prüft ob ein CVE-Eintrag ein Techstack-Produkt betrifft.

        Bidirektionaler Substring-Match: Techstack-Name steckt im
        CVE-Produkt ODER umgekehrt (für kurze CVE-Produktnamen).
        Fehlt das Feld ``betroffene_produkte``, ist kein Match möglich.

        Args:
            cve: CVE-Eintrag aus dem Cache.
            produktnamen: Liste aktiver Tech-Stack-Produktnamen.

        Returns:
            True wenn mindestens ein Treffer vorliegt.
        """
        betroffen = getattr(cve, "betroffene_produkte", None) or []
        if not betroffen:
            return False
        stack_lower = [p.lower() for p in produktnamen]
        for produkt in betroffen:
            produkt_lower = (produkt or "").lower()
            if not produkt_lower:
                continue
            for stack_name in stack_lower:
                if stack_name in produkt_lower or produkt_lower in stack_name:
                    return True
        return False
