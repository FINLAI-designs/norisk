"""
patch_eol_resolver — End-of-Life-Status fuer installierte Software Stop-Step A).

Liefert pro (vendor, product, version) eine:class:`EolStatus`. Software die
End-of-Life ist erhaelt kein Sicherheits-Patch mehr, ist aber haeufig
weiterhin im Einsatz — der Patch-Monitor zeigt das mit der Empfehlungs-
Klasse ``eol_no_patch`` Stop-Step B).

Architektur — Strategy-Pattern:
    *:class:`IEolResolver` — Protocol fuer austauschbare Quellen.
    *:class:`CuratedEolResolver` — kuratiertes Set bekannter EOL-Produkte,
      offline-safe, keine Netzwerk-Abhaengigkeit. Default fuer v1.
    *:class:`EndoflifeApiResolver` — Stub fuer kuenftige endoflife.date-
      Anbindung mit lokalem Cache (analog ``nvd_cache.db``). Wird in einem
      eigenen Folge-Sprint implementiert.

Schichtzugehoerigkeit: ``core/`` — Domain-Service, kein GUI-Import, keine
Datenbank.

Author: Patrick Riederich
Version: 1.0 Stop-Step A, 2026-05-12)
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from core.logger import get_logger
from core.patch_eol_cache import EolCacheRepository

log = get_logger(__name__)

#: Slug-Whitelist — endoflife.date-Slugs sind kebab-case-ASCII.
#: Werte in ``endoflife_product_map.json`` die nicht matchen werden
#: beim Laden verworfen (URL-Injection-Schutz, Security-Review).
_VALID_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]*$")


@dataclass(frozen=True, slots=True)
class EolStatus:
    """Resolutions-Ergebnis fuer eine Software-Produkt-Version-Kombination.

    Frozen + slots: unveraenderbar, speicherarm, hashable.

    Attributes:
        is_eol: ``True`` wenn die Produkt-Version End-of-Life ist
                     (kein Vendor-Support, keine Patches).
        cycle: Lesbarer Lifecycle-Name (z. B. ``"Windows 7"`` oder
                     ``"Office 2010"``). ``None`` wenn nicht ermittelbar.
        eol_date: ISO-Datum (``YYYY-MM-DD``) des Vendor-EOL. ``None``
                     wenn kein konkretes Datum vorliegt.
        replacement: Empfohlene Nachfolge-Version oder Migration-Strategie
                     (User-lesbar, fuer das UI Detail-Panel). ``None``
                     wenn keine Empfehlung dokumentiert ist.
        source: Provenance-String fuer den:class:`PatchScanResult`-
                     Audit-Trail. Format: ``"<resolver>:<eintrag>"``,
                     z. B. ``"curated:office_2010"`` oder
                     ``"endoflife.date:windows-server:2008-r2"``.
                     Leer wenn ``is_eol=False``.
    """

    is_eol: bool
    cycle: str | None = None
    eol_date: str | None = None
    replacement: str | None = None
    source: str = ""

    @classmethod
    def not_eol(cls) -> EolStatus:
        """Sentinel-Result fuer "kein EOL ermittelt"."""
        return cls(is_eol=False)


@runtime_checkable
class IEolResolver(Protocol):
    """Strategy-Interface fuer EOL-Datenquellen.

    Implementierungen entscheiden, ob ein konkreter Eintrag aus einer
    kuratierten Liste, der endoflife.date-API oder einer eigenen DB
    kommt. Der Patch-Monitor sieht nur dieses Interface.
    """

    def resolve(
        self,
        vendor: str | None,
        product: str,
        version: str,
    ) -> EolStatus:
        """Loest EOL-Status fuer (vendor, product, version) auf.

        Args:
            vendor: Hersteller-String aus dem CPE (z. B. ``"microsoft"``).
                     ``None`` wenn nicht ermittelbar.
            product: Produkt-Name, normalisiert. Resolver darf zusaetzliche
                     Normalisierung anwenden (lowercase, Whitespace-Trim).
            version: Installierte Version (z. B. ``"6.1.7601"`` fuer
                     Windows 7). Resolver entscheidet ueber Matching-
                     Praezision (Substring, Prefix, Range).

        Returns:
:class:`EolStatus`. Wenn kein Match: ``EolStatus.not_eol``.
        """
        ...


# ---------------------------------------------------------------------------
# Curated Resolver — offline-safe, hardcoded Liste bekannter EOL-Produkte
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _CuratedEntry:
    """Ein Eintrag in der kuratierten EOL-Liste.

    Matching: ``vendor`` + ``product_match`` (substring, case-insensitiv)
    + ``version_prefix`` (Prefix-Match auf der installierten Version).
    Wenn ``vendor`` ``None`` ist, wird der Vendor-Check uebersprungen
    (z. B. fuer plattformuebergreifende EOL-Standards).
    """

    vendor: str | None
    product_match: str
    version_prefix: str
    cycle: str
    eol_date: str
    replacement: str
    source_key: str


#: Kuratierte EOL-Liste — Stand 2026-05-12. Pflege erfolgt manuell beim
#: Folge-PR von endoflife.date-Anbindung Folge). Patrick-Konvention:
#: nur Produkte die in mittelstaendischen DACH-Setups noch real auftauchen
#: (also keine 2003er-Server-Migrations-Faelle die nur Hyperscaler-Audit
#: betreffen).
_CURATED_ENTRIES: tuple[_CuratedEntry, ...] = (
    _CuratedEntry(
        vendor="microsoft",
        product_match="windows",
        version_prefix="6.1",
        cycle="Windows 7 / Server 2008 R2",
        eol_date="2020-01-14",
        replacement="Windows 10/11 Migration oder ESU-Vertrag",
        source_key="curated:windows_7",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="windows",
        version_prefix="6.2",
        cycle="Windows 8 / Server 2012",
        eol_date="2023-10-10",
        replacement="Windows 10/11 oder Server 2019/2022",
        source_key="curated:windows_8",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="windows",
        version_prefix="6.3",
        cycle="Windows 8.1 / Server 2012 R2",
        eol_date="2023-10-10",
        replacement="Windows 10/11 oder Server 2019/2022",
        source_key="curated:windows_8_1",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="office",
        version_prefix="12.",
        cycle="Office 2007",
        eol_date="2017-10-10",
        replacement="Microsoft 365 oder neuere Office-Version",
        source_key="curated:office_2007",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="office",
        version_prefix="14.",
        cycle="Office 2010",
        eol_date="2020-10-13",
        replacement="Microsoft 365 oder neuere Office-Version",
        source_key="curated:office_2010",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="office",
        version_prefix="15.",
        cycle="Office 2013",
        eol_date="2023-04-11",
        replacement="Microsoft 365 oder neuere Office-Version",
        source_key="curated:office_2013",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="internet_explorer",
        version_prefix="11",
        cycle="Internet Explorer 11",
        eol_date="2022-06-15",
        replacement="Microsoft Edge",
        source_key="curated:ie_11",
    ),
    _CuratedEntry(
        vendor="adobe",
        product_match="flash",
        version_prefix="",  # alle Versionen
        cycle="Adobe Flash Player",
        eol_date="2020-12-31",
        replacement="HTML5 / Anwendung migrieren",
        source_key="curated:flash",
    ),
    _CuratedEntry(
        vendor=None,  # Python ist Open-Source, kein zentraler Vendor-Eintrag
        product_match="python",
        version_prefix="2.",
        cycle="Python 2.x",
        eol_date="2020-01-01",
        replacement="Python 3.9+",
        source_key="curated:python_2",
    ),
    _CuratedEntry(
        vendor="microsoft",
        product_match="vcredist",
        version_prefix="9.",
        cycle="Visual C++ 2008 Redistributable",
        eol_date="2018-04-10",
        replacement="VC++ 2015-2022 Redistributable",
        source_key="curated:vcredist_2008",
    ),
)


class CuratedEolResolver:
    """Offline-EOL-Resolver auf Basis einer hardcoded Liste.

    Vorteil gegenueber API-basierten Resolvern: keine Netzwerk-
    Abhaengigkeit, keine Rate-Limits, vorhersagbare Antwortzeit.
    Nachteil: muss bei neuen EOL-Wellen manuell ergaenzt werden. Patrick-
    Konvention 2026-05-12: nur DACH-Mittelstands-relevante Eintraege
    aufnehmen, keine Server-Migrations-Klein-Klein.

    Threadsafe — die Eintragstabelle ist Modul-Tuple (immutable), die
    Resolver-Instanz haelt keinen State.
    """

    def __init__(
        self,
        entries: tuple[_CuratedEntry, ...] | None = None,
    ) -> None:
        """Initialisiert den Resolver.

        Args:
            entries: Optional eine eigene Liste — Tests injizieren hier
                Mock-Eintraege ohne:data:`_CURATED_ENTRIES` zu mutieren.
                ``None`` (Default) → Produktive Liste.
        """
        self._entries = entries if entries is not None else _CURATED_ENTRIES

    def resolve(
        self,
        vendor: str | None,
        product: str,
        version: str,
    ) -> EolStatus:
        """Sucht einen Match in der kuratierten Liste.

        Matching-Reihenfolge:
            1. Vendor-Check (case-insensitiv) — wenn der Eintrag einen
               ``vendor`` hat, muss er mit dem Input-Vendor uebereinstimmen.
            2. Product-Substring (case-insensitiv, lowercase + underscores
               normalisiert).
            3. Version-Prefix — der Input muss mit ``version_prefix``
               beginnen. Leer-Prefix matcht jede Version (z. B. Flash).

        Erster Treffer gewinnt — die Liste ist von "spezifisch zu allgemein"
        sortiert.
        """
        if not product:
            return EolStatus.not_eol()
        product_norm = _normalize_product(product)
        vendor_norm = (vendor or "").lower().strip()

        for entry in self._entries:
            if entry.vendor is not None and entry.vendor.lower() != vendor_norm:
                continue
            if entry.product_match.lower() not in product_norm:
                continue
            if entry.version_prefix and not version.startswith(entry.version_prefix):
                continue
            return EolStatus(
                is_eol=True,
                cycle=entry.cycle,
                eol_date=entry.eol_date,
                replacement=entry.replacement,
                source=entry.source_key,
            )

        return EolStatus.not_eol()


def _normalize_product(product: str) -> str:
    """Normalisiert einen Produkt-Namen fuer den Vergleich.

    Lowercase + Whitespace zu Underscore (CPE-Konvention). Damit matcht
    ``"Internet Explorer"`` gegen ``"internet_explorer"``.
    """
    return product.lower().strip().replace(" ", "_").replace("-", "_")


# ---------------------------------------------------------------------------
# Stub: endoflife.date-API-Resolver (Folge-Sprint)
# ---------------------------------------------------------------------------


#: Default-URL-Template fuer endoflife.date. ``{slug}`` wird beim Fetch
#: ersetzt. Im Test kann eine andere Base-URL injiziert werden.
_ENDOFLIFE_API_URL_TEMPLATE: str = "https://endoflife.date/api/{slug}.json"

#: Rate-Limit: konservativ 10 req/min (endoflife.date erlaubt mehr,
#: aber wir wollen kein noisy Neighbor sein). Token-Bucket mit
#: Burst = 10, Refill = 1 Token alle 6 s.
_RATE_LIMIT_BURST: int = 10
_RATE_LIMIT_REFILL_INTERVAL_S: float = 6.0

#: Default-Pfad zur Produkt-Mapping-JSON. Tests koennen einen anderen
#: Pfad injizieren.
_DEFAULT_PRODUCT_MAP_PATH: str = "core/data/endoflife_product_map.json"


class _TokenBucket:
    """Einfacher Token-Bucket fuer das Rate-Limit.

    Threadsafe: ein Lock schuetzt den State. ``acquire`` blockiert *nicht*
    — der Caller bekommt False zurueck und entscheidet selbst (Resolver
    faellt dann auf Stale-Cache oder ``not_eol`` zurueck).
    """

    def __init__(
        self,
        *,
        burst: int = _RATE_LIMIT_BURST,
        refill_interval_s: float = _RATE_LIMIT_REFILL_INTERVAL_S,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._burst = burst
        self._refill_interval = refill_interval_s
        self._tokens: float = float(burst)
        import time  # noqa: PLC0415

        self._now = now_fn or time.monotonic
        self._last_refill = self._now()
        import threading  # noqa: PLC0415

        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Returns: True wenn ein Token verfuegbar war."""
        with self._lock:
            now = self._now()
            elapsed = now - self._last_refill
            if elapsed > 0:
                refill = elapsed / self._refill_interval
                self._tokens = min(self._burst, self._tokens + refill)
                self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class EndoflifeApiResolver:
    """endoflife.date-API-Resolver mit Cache + Rate-Limit.

    Pipeline pro:meth:`resolve`-Call:

        1. Vendor/Product → endoflife-Slug via Mapping-JSON.
           Kein Match → ``EolStatus.not_eol`` (kein Crash).
        2. Cache-Lookup: frischer Eintrag → direkt aus Cache.
        3. Cache stale oder leer → HTTP-Fetch (mit Rate-Limit-Check).
           Rate-Limit blockiert → Stale-Cache nutzen oder ``not_eol``.
        4. Cycle-Match: Installed-Version gegen die ``cycle``-Eintraege
           der API-Antwort. Wenn der zugehoerige Cycle ``eol: true``
           oder ein vergangenes ``eol``-Datum hat → ``is_eol=True``.

    Architektur-Spec: ``IEolResolver``-Protocol — austauschbar zum
:class:`CuratedEolResolver`. Wenn Patrick beide nutzen will, kann
    er ein:class:`CompositeEolResolver` schreiben (curated zuerst,
    bei Miss zur API fragen). Fuer v1 sind sie alternativ.

    Defensive: Jeder Fehler (Network down, JSON kaputt, Cache-Schreib-
    fehler) faellt auf ``not_eol`` zurueck. Es gibt keinen Crash-Pfad.
    """

    def __init__(
        self,
        *,
        cache: EolCacheRepository | None = None,
        rate_limiter: _TokenBucket | None = None,
        url_template: str = _ENDOFLIFE_API_URL_TEMPLATE,
        product_map: dict[str, str] | None = None,
        product_map_path: str = _DEFAULT_PRODUCT_MAP_PATH,
        http_timeout_s: float = 10.0,
        http_get: Callable[[str, float], str] | None = None,
    ) -> None:
        """Initialisiert den Resolver.

        Args:
            cache: Optional vorbereiteter Cache. Default:
                neue Instanz mit Default-TTL.
            rate_limiter: Optional eigener Token-Bucket (Tests).
            url_template: URL-Template mit ``{slug}``-Placeholder
                (Tests koennen lokalen Server einspeisen).
            product_map: Optional vorbereitetes Mapping
                (Tests). Default: aus ``product_map_path`` laden.
            product_map_path: Pfad zur Mapping-JSON.
            http_timeout_s: Subprocess-Timeout.
            http_get: Optional eine GET-Funktion
                ``(url, timeout) → json_str`` — Tests mocken hier.
                Default: ``urllib.request``-basiert.
        """
        self._cache = cache or EolCacheRepository()
        self._rate_limiter = rate_limiter or _TokenBucket()
        self._url_template = url_template
        self._http_timeout = http_timeout_s
        self._http_get = http_get or _default_http_get
        if product_map is not None:
            self._product_map = product_map
        else:
            self._product_map = _load_product_map(product_map_path)

    def resolve(
        self,
        vendor: str | None,
        product: str,
        version: str,
    ) -> EolStatus:
        """Siehe Modul-Doc fuer die Pipeline."""
        if not product:
            return EolStatus.not_eol()

        slug = self._lookup_slug(vendor, product)
        if slug is None:
            return EolStatus.not_eol()

        cycles = self._fetch_or_cache(slug)
        if cycles is None:
            return EolStatus.not_eol()

        return _match_version_to_eol(cycles, version, slug)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _lookup_slug(self, vendor: str | None, product: str) -> str | None:
        """Mapping vendor+product → endoflife-Slug.

        Drei-Stufen-Match:
            1. Exakter Lookup ``vendor:product`` im Mapping.
            2. Vendor-freier Lookup ``:product`` (Mapping-Eintraege ohne
               Vendor-Komponente, z. B. ``":python"``).
            3. Substring-Match — der **laengste** matchende ``map_product``
               gewinnt. Damit landet ``"windows_server_2019"`` korrekt
               beim Slug ``windows-server`` (nicht ``windows``), weil
               ``"windows_server"`` (Laenge 14) > ``"windows"`` (Laenge 7).
        """
        vendor_norm = (vendor or "").lower().strip()
        product_norm = _normalize_product(product)
        # 1. Exakter Lookup
        key = f"{vendor_norm}:{product_norm}"
        if key in self._product_map:
            return self._product_map[key]
        # 2. Vendor-Free Lookup (Eintraege mit leerem vendor)
        free_key = f":{product_norm}"
        if free_key in self._product_map:
            return self._product_map[free_key]
        # 3. Substring-Match — laengster matchender map_product gewinnt
        # (verhindert dass "windows" vor "windows_server" feuert).
        best_slug: str | None = None
        best_length = -1
        for map_key, slug in self._product_map.items():
            if map_key.startswith("_"):
                continue  # Comment-Keys (z. B. "_comment", "_schema")
            map_vendor, _, map_product = map_key.partition(":")
            if map_vendor and map_vendor != vendor_norm:
                continue
            if not map_product:
                continue
            if map_product in product_norm and len(map_product) > best_length:
                best_slug = slug
                best_length = len(map_product)
        return best_slug

    def _fetch_or_cache(self, slug: str) -> list[dict] | None:
        """Cache-first Lookup. Returnt ``None`` bei Total-Fail."""
        cached = self._cache.get(slug)
        if cached is not None and not cached.is_stale:
            return cached.cycles
        # Stale-or-miss: versuche HTTP-Fetch
        if not self._rate_limiter.try_acquire():
            log.info(
                "Rate-Limit blockiert endoflife-Fetch fuer %s — "
                "nutze Stale-Cache falls vorhanden.",
                slug,
            )
            return cached.cycles if cached is not None else None

        url = self._url_template.format(slug=slug)
        try:
            raw = self._http_get(url, self._http_timeout)
        except Exception as exc:  # noqa: BLE001 — Network-Fehler darf nie crashen
            log.warning(
                "endoflife.date-Fetch %s fehlgeschlagen: %s — "
                "Stale-Cache-Fallback.",
                slug, type(exc).__name__,
            )
            return cached.cycles if cached is not None else None

        try:
            import json as _json  # noqa: PLC0415

            data = _json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "endoflife.date-Antwort fuer %s nicht JSON-parsbar: %s",
                slug, type(exc).__name__,
            )
            return cached.cycles if cached is not None else None

        if not isinstance(data, list):
            log.warning(
                "endoflife.date-Antwort fuer %s ist keine Liste — ignoriere.",
                slug,
            )
            return cached.cycles if cached is not None else None

        # Cache schreiben (fail-soft)
        try:
            self._cache.set(slug, data)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "EolCacheRepository.set fuer %s fehlgeschlagen: %s",
                slug, type(exc).__name__,
            )

        return data


def _default_http_get(url: str, timeout_s: float) -> str:
    """Stdlib-only HTTP-GET. Keine extra-Dependency."""
    import urllib.request  # noqa: PLC0415

    # Wir trusten dem hardcoded api.endoflife.date-Endpunkt; keine
    # Open-URL-Konfiguration durch User-Input (Injection-Schutz).
    req = urllib.request.Request(  # noqa: S310 — fixed-base URL, kein User-Input
        url,
        headers={"User-Agent": "NoRisk-by-FINLAI/1.0 (security-tool)"},
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 # nosec B310 — fixed-base URL, kein User-Input
        return resp.read().decode("utf-8")


def _load_product_map(path: str) -> dict[str, str]:
    """Liest die Produkt-Mapping-JSON. Fehler → leeres Dict.

    Funktioniert sowohl im Dev-Modus (Pfad relativ zum Repo-Root) als
    auch im gebuendelten Modus (PyInstaller: ``sys._MEIPASS``). Slug-
    Werte werden gegen:data:`_VALID_SLUG_RE` whitelisted — kaputte
    Eintraege werden verworfen.
    """
    import json as _json  # noqa: PLC0415
    import sys as _sys  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    if getattr(_sys, "frozen", False):
        # PyInstaller: Bundle-Root = sys._MEIPASS
        candidate = Path(_sys._MEIPASS) / path  # type: ignore[attr-defined] # noqa: SLF001
    else:
        candidate = Path(__file__).resolve().parent.parent / path
    if not candidate.is_file():
        log.warning(
            "endoflife_product_map.json nicht gefunden unter %s — "
            "Resolver kann keine Produkte mappen.",
            candidate,
        )
        return {}
    try:
        with candidate.open("r", encoding="utf-8") as f:
            data = _json.load(f)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "endoflife_product_map.json kaputt: %s — leeres Mapping.",
            type(exc).__name__,
        )
        return {}

    result: dict[str, str] = {}
    for raw_key, raw_val in data.items():
        key = str(raw_key)
        if not isinstance(raw_val, str):
            continue
        # Comment-Keys (``_*``) behalten den Inhalt — _lookup_slug ueberspringt
        # sie. Sie matchen nie eine echte Slug-URL.
        if key.startswith("_"):
            result[key] = raw_val
            continue
        if not _VALID_SLUG_RE.fullmatch(raw_val):
            log.warning(
                "endoflife_product_map: Slug-Wert %r fuer Key %r ist nicht "
                "kebab-case-ASCII — wird ignoriert.",
                raw_val, key,
            )
            continue
        result[key] = raw_val
    return result


def _match_version_to_eol(
    cycles: list[dict],
    installed_version: str,
    slug: str,
) -> EolStatus:
    """Mappt die Installed-Version auf einen Cycle-Eintrag und prueft EOL.

    endoflife.date-Cycle-Format:
        {
          "cycle": "16.0",
          "releaseDate": "2018-12-19",
          "eol": "2027-04-13", ← Datum oder bool
          "latest": "16.0.16130",
...
        }

    Match-Strategie: ``cycle``-Prefix gegen ``installed_version`` — der
    laengste passende Cycle gewinnt (z. B. "16.0" vor "16").
    """
    if not cycles:
        return EolStatus.not_eol()

    # Cycles nach Prefix-Match sortieren, laengster Prefix zuerst.
    # Versions-Grenze-Check: nach dem Cycle-Prefix muss ein Versions-Trenner
    # (``.`` oder ``-``) kommen oder die Version dort enden. Damit matcht
    # Cycle ``"16"`` nicht ``"160.0"`` (anderer Major).
    matched_cycle: dict | None = None
    matched_prefix_len = -1
    for cycle in cycles:
        cycle_str = str(cycle.get("cycle", ""))
        if not cycle_str:
            continue
        if not installed_version.startswith(cycle_str):
            continue
        # Boundary-Check: nach Prefix muss Versions-Trenner stehen, oder
        # die Version endet hier exakt.
        tail = installed_version[len(cycle_str):]
        if tail and tail[0] not in (".", "-"):
            continue
        if len(cycle_str) > matched_prefix_len:
            matched_cycle = cycle
            matched_prefix_len = len(cycle_str)

    if matched_cycle is None:
        return EolStatus.not_eol()

    eol_field = matched_cycle.get("eol")
    is_eol = False
    eol_date: str | None = None
    if isinstance(eol_field, bool):
        is_eol = eol_field
    elif isinstance(eol_field, str) and eol_field:
        eol_date = eol_field
        try:
            from datetime import date as _date  # noqa: PLC0415

            parsed = _date.fromisoformat(eol_field)
            is_eol = parsed <= _date.today()
        except ValueError:
            is_eol = False

    if not is_eol:
        return EolStatus.not_eol()

    cycle_label = str(matched_cycle.get("cycle", "unknown"))
    return EolStatus(
        is_eol=True,
        cycle=f"{slug.title()} {cycle_label}",
        eol_date=eol_date,
        replacement=None,
        source=f"endoflife.date:{slug}:{cycle_label}",
    )


__all__ = [
    "CuratedEolResolver",
    "EndoflifeApiResolver",
    "EolStatus",
    "IEolResolver",
]
