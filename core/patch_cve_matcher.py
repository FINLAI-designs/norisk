"""
patch_cve_matcher — CVE-Treffer fuer ein Software-Inventar via NVD.

PM-1.5. Thin Wrapper um den existierenden
:class:`tools.cyber_dashboard.application.nvd_service.NvdService` —
keine Duplikate, keine eigene HTTP/Cache/Retry-Schicht. Wir
konsumieren die bestehende NVD-Integration und mappen das
Ergebnis auf eine PatchMonitor-spezifische
:class:`CveMatch`-Datenklasse.

Aufloesungs-Pfad in:meth:`CveMatcher.get_cves`::

    cpe → product extrahieren → NvdService.suche_produkt(product, 180d)
        → CveEintrag-Liste → OS-Filter → Convert → CveMatch-Liste

In-Memory-Cache (kein Disk-Persistenz) reduziert wiederholte
NVD-Calls innerhalb einer Session: 24h TTL, 100-Eintrag-Limit
mit 20%-Eviction der aeltesten Eintraege.

**Bekannte Limitierungen** (PM-1.5 MVP, P2-Enhancement spaeter):

* Die existierende:class:`NvdService.suche_produkt` ist eine
  Keyword-Suche — sie findet alle CVEs, die das Produkt im Namen
  erwaehnen, ohne CPE-Praezision. Konsequenz: leichte
  Ueber-Inklusion (lieber False-Positive als verpasste CVEs).
* Version-Range-Matching wird best-effort aus dem
  ``affected_versions``-String parsed (``"before X.Y"`` /
  ``"< X.Y"``). NVD-API-Felder ``versionEndExcluding`` etc. sind
  via NvdService nicht direkt verfuegbar — eine kuenftige
  Erweiterung von NvdService um ``suche_cpe(cpe)`` mit dem
  ``cpeName``-API-Parameter wuerde das beheben.
* OS-Filter ist eine Description-Heuristik — es gibt aktuell
  keinen direkten Zugriff auf die ``configurations.cpeMatch``-Daten
  fuer die OS-Komponente.

Bei JEDEM Fehler in:meth:`CveMatcher.get_cves` (NVD offline, kein
API-Key, Parse-Error) → leere Liste + Log-Warning. Kein Crash —
der Patch-Scan laeuft weiter, nur ohne CVE-Anreicherung fuer dieses
eine Item.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.logger import get_logger
from core.patch_normalizer import normalize_version
from core.patch_result import PatchScanResult

if TYPE_CHECKING:
    from core.patch_channel_resolver import ChannelDecision
    from tools.cyber_dashboard.application.nvd_service import NvdService
    from tools.cyber_dashboard.domain.models import CveEintrag

log = get_logger(__name__)


@dataclass(frozen=True)
class CveMatch:
    """Ein CVE-Treffer fuer ein Inventar-Item.

    Attributes:
        cve_id: NVD-Identifikator (z.B. ``"CVE-2024-1234"``).
        cvss_score: Numerischer CVSS-Score ``[0.0, 10.0]``. ``0.0``
            wenn der NVD-Eintrag keine CVSS-Metrik hat (selten,
            meist nur ganz frische CVEs).
        cvss_version: ``"3.1"`` / ``"3.0"`` / ``"2.0"`` —
            welche CVSS-Variante zugrunde liegt. NvdService bevorzugt
            v3.1, fallt auf v3.0 / v2 zurueck.
        description: Englische Beschreibung (max. 300 Zeichen,
            wird vom NvdService gekappt).
        exploit_available: ``True`` wenn das CVE in der CISA-
            KEV-Liste (Known Exploited Vulnerabilities) steht.
        published: ISO-Datum der Erstveroeffentlichung.
        affected_versions: Freitext-Beschreibung der betroffenen
            Versionen ("vendor product / vendor product"). Wird
            heuristisch von:func:`_extract_version_bound` geparst.
    """

    cve_id: str
    cvss_score: float
    cvss_version: str
    description: str
    exploit_available: bool
    published: str
    affected_versions: str


class CveMatcher:
    """Reichert:class:`ChannelDecision` mit CVE-Daten an.

    Wird typischerweise einmal pro Inventar-Sammeldurchlauf
    instanziiert. NVD-Service wird lazy konstruiert — falls der
    User keinen NVD-API-Key gesetzt hat oder die DB fehlt,
    schlaegt die Konstruktion an:meth:`CveMatcher.get_cves` selbst
    fehl (per try/except) und liefert leere CVE-Listen.
    """

    _CACHE_LIMIT = 100
    _EVICTION_FRACTION = 0.20

    def __init__(
        self,
        nvd: NvdService | None = None,
        cache_ttl_hours: int = 24,
    ) -> None:
        """Initialisiert den Matcher.

        Args:
            nvd: Optional vorbereitete NvdService-Instanz. In Tests
                wird ein Mock injiziert; im Produktivpfad bleibt das
                Default — bei der ersten:meth:`get_cves`-Anfrage
                wird ein neuer:class:`NvdService` konstruiert (mit
                SecureStorage-Lookup fuer den API-Key).
            cache_ttl_hours: TTL des In-Memory-Caches in Stunden
                (Default 24).
        """
        self._nvd = nvd
        self._cache_ttl = cache_ttl_hours * 3600
        self._cache: dict[str, list[CveMatch]] = {}
        self._cache_timestamps: dict[str, float] = {}

    def _get_nvd(self) -> NvdService:
        """Lazy-Initialisierung des NvdService."""
        if self._nvd is None:
            from tools.cyber_dashboard.application.nvd_service import (  # noqa: PLC0415
                NvdService,
            )

            self._nvd = NvdService()
        return self._nvd

    def get_cves(
        self,
        cpe: str | None,
        version: str | None = None,
    ) -> list[CveMatch]:
        """Liefert CVE-Treffer fuer einen CPE-String.

        Cache-Key ist der CPE-String (ohne Version — das Version-
        Filtering laeuft post-cache, damit ``CveMatcher`` fuer
        unterschiedliche installierte Versionen keine separaten
        NVD-Calls macht).

        Args:
            cpe: CPE-2.3-String aus:func:`core.patch_cpe.build_cpe`.
                ``None`` → leere Liste (kein NVD-Call).
            version: Optional die installierte Version fuer
                Range-Filtering. ``None`` → kein Filter.

        Returns:
            Liste der relevanten:class:`CveMatch`-Objekte. Leer bei
            Fehler / ohne CPE / wenn keine CVEs in NVD gefunden.
        """
        if not cpe:
            return []

        now = time.time()
        cached = self._cache.get(cpe)
        ts = self._cache_timestamps.get(cpe, 0.0)
        if cached is not None and (now - ts) < self._cache_ttl:
            log.debug("CveMatcher: cache-hit %s", cpe[:60])
            return self._filter_by_version(cached, version)

        try:
            entries = self._fetch(cpe)
        except Exception as e:  # noqa: BLE001 — fail-open by design
            log.warning(
                "CveMatcher.get_cves(%r) fehlgeschlagen: %s — leere Liste",
                cpe, e,
            )
            return []

        relevant = [e for e in entries if _is_windows_relevant(e)]
        matches = [_to_match(e) for e in relevant]
        self._cache_set(cpe, matches, now)
        return self._filter_by_version(matches, version)

    def enrich_decision(
        self,
        decision: ChannelDecision,
        available_version: str | None = None,
    ) -> PatchScanResult:
        """Konstruiert ein:class:`PatchScanResult` aus einer
:class:`ChannelDecision` plus CVE-Daten und der
        ``available_version`` (PM-1.8).

        Wenn:attr:`ChannelDecision.cpe` ``None`` ist (z.B. unbekannte
        Multi-Token-Software ohne winget-Id), werden ``cve_ids=``,
        ``cvss_max=None`` gesetzt — kein NVD-Call. Die
        ``available_version`` wird trotzdem mitgefuehrt (PatchScanResult-
        Feld), damit die UI den verfuegbaren Patch anzeigen kann.

        Args:
            decision: Aus dem ChannelResolver.
            available_version: Optional aus dem im PatchService gebauten
                Lookup-Dict ``{item.winget_id: item.latest_available}``
                (nur Microsoft.WinGet.Client-Modul-Pfad fuellt das Feld).
                ``None`` wenn kein winget-Id oder kein Update verfuegbar.
        """
        cves = self.get_cves(decision.cpe, decision.item.version)
        return PatchScanResult.from_decision_and_cves(
            decision, cves, available_version=available_version
        )

    # ------------------------------------------------------------------
    # interne Hilfen
    # ------------------------------------------------------------------

    def _fetch(self, cpe: str) -> list[CveEintrag]:
        product = _extract_product(cpe)
        if not product:
            return []
        nvd = self._get_nvd()
        return nvd.suche_produkt(product, tage=180)

    def _cache_set(
        self,
        key: str,
        value: list[CveMatch],
        now: float,
    ) -> None:
        if len(self._cache) >= self._CACHE_LIMIT:
            self._evict_oldest()
        self._cache[key] = value
        self._cache_timestamps[key] = now

    def _evict_oldest(self) -> None:
        n = max(1, int(len(self._cache) * self._EVICTION_FRACTION))
        oldest = sorted(
            self._cache_timestamps.items(), key=lambda kv: kv[1]
        )[:n]
        for key, _ts in oldest:
            self._cache.pop(key, None)
            self._cache_timestamps.pop(key, None)

    @staticmethod
    def _filter_by_version(
        matches: list[CveMatch],
        version: str | None,
    ) -> list[CveMatch]:
        if version is None:
            return matches
        installed = _safe_version(normalize_version(version))
        if installed is None:
            return matches
        return [m for m in matches if _is_potentially_affected(m, installed)]


# ---------------------------------------------------------------------
# Reine Hilfsfunktionen — modul-level fuer Testbarkeit
# ---------------------------------------------------------------------


def _extract_product(cpe: str) -> str | None:
    """Extrahiert den Produkt-Teil aus einem CPE-2.3-String.

    ``"cpe:2.3:a:mozilla:firefox:121.0:..."`` → ``"firefox"``.

    Wandelt CPE-Escapes (``\\+`` → ``+``) und Underscores zu
    Leerzeichen zurueck — fuer die NVD-Keyword-Suche brauchen wir
    den nutzerlesbaren Produkt-String.
    """
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    product = parts[4]
    if not product or product == "*":
        return None
    # CPE-Escaping rueckgaengig
    product = product.replace(r"\+", "+")
    product = product.replace("_", " ")
    return product.strip() or None


_OS_ONLY_PHRASES: tuple[str, ...] = (
    "linux only",
    "macos only",
    "only on linux",
    "only on macos",
)


def _is_windows_relevant(entry: CveEintrag) -> bool:
    """Best-effort OS-Filter via Description-Heuristik.

    Da der bestehende:class:`NvdService` die ``configurations``-
    Daten der NVD-Antwort nicht durchreicht, koennen wir nur
    auf den Beschreibungstext schauen. Default: ``True`` (behalten
    — lieber False-Positive als verpasstes CVE).

    Filter-Logik:

    * ``"windows"`` im Text → behalten (auch wenn andere OS auch
      genannt sind — Cross-Platform-CVE).
    * Sonst: aussortieren wenn eine der Linux/macOS-only-Phrasen
      vorkommt (:data:`_OS_ONLY_PHRASES`).
    """
    desc = (entry.beschreibung or "").lower()
    if "windows" in desc:
        return True
    return not any(p in desc for p in _OS_ONLY_PHRASES)


def _to_match(entry: CveEintrag) -> CveMatch:
    """Mappt einen:class:`CveEintrag` (NvdService) auf
:class:`CveMatch` (PatchMonitor)."""
    return CveMatch(
        cve_id=entry.cve_id,
        cvss_score=entry.cvss_score,
        cvss_version="3.1",  # NvdService bevorzugt v3.1; nicht direkt exponiert
        description=entry.beschreibung,
        exploit_available=entry.cisa_kev,
        published=entry.veroeffentlicht.isoformat(),
        affected_versions=", ".join(entry.betroffene_produkte) or "unbekannt",
    )


_VERSION_BOUND_PAT = re.compile(
    r"(?:before|<\s*|prior to)\s*(\d+(?:\.\d+){0,3})", re.IGNORECASE
)


def _safe_version(raw: str | None):
    """Wrappt:class:`packaging.version.Version` mit Fehler-Schutz."""
    if not raw:
        return None
    try:
        from packaging.version import (  # noqa: PLC0415
            InvalidVersion,
            Version,
        )
    except ImportError:
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _is_potentially_affected(match: CveMatch, installed) -> bool:
    """Prueft, ob die installierte Version potenziell betroffen ist.

    Heuristik: sucht in:attr:`CveMatch.affected_versions` nach
    ``"before X.Y"`` / ``"< X.Y"`` / ``"prior to X.Y"`` und
    vergleicht. Bei nicht parsbarer Range: ``True``
    ("moeglicherweise betroffen" — lieber False-Positive).
    """
    pat = _VERSION_BOUND_PAT.search(match.affected_versions)
    if pat is None:
        return True  # keine Range erkennbar → potentiell betroffen
    bound = _safe_version(pat.group(1))
    if bound is None:
        return True  # Range-String nicht parsbar
    try:
        return installed < bound
    except TypeError:
        return True
