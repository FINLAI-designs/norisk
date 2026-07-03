"""
detectors — Drei Auto-Detection-Quellen fuer Vendor-Vorschlaege.

Iteration 2b:

-:class:`InstalledAppsDetector` — wrapt
  ``tools.system_scanner.data.windows_scanner._read_registry_software``
  (Windows-Registry Uninstall-Keys). Auf Non-Windows: leere Liste.
-:class:`MxLookupDetector` — DNS-MX-Auflösung via ``dnspython`` analog zu
  ``customer_audit.sovereignty_scanner._scan_dns_mx``.
-:class:`CertIssuerDetector` — TLS-Handshake via ``cert_monitor.cert_scanner``
  iteriert ueber Domain-Liste, extrahiert Issuer.

Alle drei matchen die jeweilige Pattern-Liste pro:class:`VendorCatalogEntry`
**case-insensitive Substring**. Jeder Treffer wird zu einer
:class:`VendorDetection`. Dedup pro (catalog_entry, raw_match) findet bereits
hier statt (innerhalb eines Scans), die DB-seitige Dedup uebernimmt das
Repository-Upsert.

Schichtzugehoerigkeit: application/ — darf domain + data + andere
application-Module + core importieren.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import platform
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from core.logger import get_logger
from tools.supply_chain_monitor.domain.models import (
    DetectionSource,
    VendorCatalogEntry,
    VendorDetection,
)

_log = get_logger(__name__)

# Reader-Signaturen — injizierbar fuer Tests.
InstalledAppReader = Callable[[], list[str]]
MxResolver = Callable[[str], list[str]]
CertScanner = Callable[[str], str]

# Tuning-Konstanten.
_MX_TIMEOUT_S: float = 5.0
_MAX_MX_RECORDS: int = 20
_MAX_HOSTNAME_LEN: int = 253


# ---------------------------------------------------------------------------
# Pattern-Matching — gemeinsam fuer alle drei Quellen
# ---------------------------------------------------------------------------

def _match_patterns(
    catalog: Iterable[VendorCatalogEntry],
    source: DetectionSource,
    raw_values: Iterable[str],
) -> list[VendorDetection]:
    """Erzeugt Detections fuer alle (catalog_entry, raw_value)-Treffer.

    Patterns sind in:meth:`VendorCatalogEntry.__post_init__` bereits
    lowercase + getrimmt. Wir vergleichen daher gegen ``raw_value.lower``.

    Dedup: Pro (catalog_entry_id, source, raw_value) genau **eine**
    Detection — selbst wenn mehrere Patterns desselben Entries matchen.

    Args:
        catalog: Alle bekannten Catalog-Eintraege.
        source: Die Quelle, die die Treffer liefert.
        raw_values: Roh-Strings (App-Namen / MX-Hostnames / Cert-Issuer).

    Returns:
        Liste neuer:class:`VendorDetection` (id = ``None`` — Repository
        vergibt sie beim Upsert).
    """
    now = datetime.now(UTC)
    seen: set[tuple[int, str]] = set()
    detections: list[VendorDetection] = []
    raw_pairs = [(raw, raw.lower()) for raw in raw_values if raw and raw.strip()]
    for entry in catalog:
        if entry.id is None:
            # Kann beim Test passieren — Entries OHNE persistente ID skippen.
            continue
        patterns = entry.patterns_for(source)
        if not patterns:
            continue
        for raw, raw_lc in raw_pairs:
            if not any(pattern in raw_lc for pattern in patterns):
                continue
            key = (entry.id, raw)
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                VendorDetection(
                    id=None,
                    catalog_entry_id=entry.id,
                    source=source,
                    raw_match=raw,
                    detected_at=now,
                )
            )
    return detections


# ---------------------------------------------------------------------------
# 1) Installed-Apps (Windows-Registry)
# ---------------------------------------------------------------------------


class InstalledAppsDetector:
    """Liest installierte Software aus der Windows-Registry und matched
    sie gegen die App-Patterns des:class:`VendorCatalogEntry`.

    Auf Non-Windows-Systemen liefert die Detection eine leere Liste
    (ohne Fehler) — dadurch laeuft der Supply-Chain-Monitor auch unter
    Linux/macOS ohne Crash, nur ohne diese Quelle.

    Optional kann ein eigener ``reader`` injiziert werden — sehr nuetzlich
    fuer Tests (gibt eine feste Liste von App-Namen zurueck).
    """

    source: DetectionSource = DetectionSource.INSTALLED_APP

    def __init__(self, reader: InstalledAppReader | None = None) -> None:
        self._reader = reader

    def detect(self, catalog: list[VendorCatalogEntry]) -> list[VendorDetection]:
        """Fuehrt die Detection durch.

        Args:
            catalog: Alle bekannten Catalog-Eintraege.

        Returns:
            Liste von:class:`VendorDetection` (PENDING-Status).
        """
        if not catalog:
            return []
        try:
            app_names = self._reader() if self._reader else self._read_default()
        except Exception as exc:  # noqa: BLE001 — Registry/OS-Fehler nicht ins Tool propagieren
            _log.warning(
                "InstalledAppsDetector: Reader fehlgeschlagen: %s", type(exc).__name__
            )
            return []
        if not app_names:
            return []
        return _match_patterns(catalog, self.source, app_names)

    @staticmethod
    def _read_default() -> list[str]:
        if platform.system() != "Windows":
            _log.debug("InstalledAppsDetector: Non-Windows-Plattform — leeres Ergebnis.")
            return []
        from tools.system_scanner.data.windows_scanner import (  # noqa: PLC0415
            _read_registry_software,
        )

        return [sw.name for sw in _read_registry_software() if sw.name]


# ---------------------------------------------------------------------------
# 2) MX-Lookup (dnspython)
# ---------------------------------------------------------------------------


class MxLookupDetector:
    """Resolved MX-Records fuer eine Domain-Liste und matched die MX-Hostnames
    gegen die ``mx_hostname_patterns`` der Catalog-Eintraege.

    Optional injizierbarer ``resolver``-Callable fuer Tests.
    """

    source: DetectionSource = DetectionSource.MX_LOOKUP

    def __init__(self, resolver: MxResolver | None = None) -> None:
        self._resolver = resolver

    def detect(
        self,
        catalog: list[VendorCatalogEntry],
        domains: Iterable[str],
    ) -> list[VendorDetection]:
        """Fuehrt die Detection durch.

        Args:
            catalog: Alle bekannten Catalog-Eintraege.
            domains: Domains, fuer die der MX-Lookup laufen soll.

        Returns:
            Liste von:class:`VendorDetection` (PENDING-Status).
        """
        if not catalog:
            return []
        collected: list[str] = []
        for domain in domains:
            clean = domain.strip().rstrip(".").lower()
            if not clean:
                continue
            try:
                hosts = self._resolver(clean) if self._resolver else self._resolve_default(clean)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "MxLookupDetector: Lookup %r fehlgeschlagen: %s",
                    clean,
                    type(exc).__name__,
                )
                continue
            collected.extend(hosts[:_MAX_MX_RECORDS])
        if not collected:
            return []
        return _match_patterns(catalog, self.source, collected)

    @staticmethod
    def _resolve_default(domain: str) -> list[str]:
        import dns.resolver  # noqa: PLC0415

        resolver = dns.resolver.Resolver()
        resolver.lifetime = _MX_TIMEOUT_S
        answers = resolver.resolve(domain, "MX")
        result: list[str] = []
        for rdata in list(answers)[:_MAX_MX_RECORDS]:
            host = str(getattr(rdata, "exchange", "")).rstrip(".")
            if host and len(host) <= _MAX_HOSTNAME_LEN:
                result.append(host)
        return result


# ---------------------------------------------------------------------------
# 3) Cert-Issuer (TLS-Handshake)
# ---------------------------------------------------------------------------


class CertIssuerDetector:
    """Holt das TLS-Zertifikat einer Domain und matched den Issuer-CN/O
    gegen die ``cert_issuer_patterns`` der Catalog-Eintraege.

    Optional injizierbarer ``scanner``-Callable fuer Tests.
    """

    source: DetectionSource = DetectionSource.CERT_ISSUER

    def __init__(self, scanner: CertScanner | None = None) -> None:
        self._scanner = scanner

    def detect(
        self,
        catalog: list[VendorCatalogEntry],
        domains: Iterable[str],
    ) -> list[VendorDetection]:
        """Fuehrt die Detection durch.

        Args:
            catalog: Alle bekannten Catalog-Eintraege.
            domains: Domains, fuer die der TLS-Handshake laufen soll.

        Returns:
            Liste von:class:`VendorDetection` (PENDING-Status).
        """
        if not catalog:
            return []
        collected: list[str] = []
        for domain in domains:
            clean = domain.strip().rstrip(".").lower()
            if not clean:
                continue
            try:
                issuer = self._scanner(clean) if self._scanner else self._scan_default(clean)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "CertIssuerDetector: Scan %r fehlgeschlagen: %s",
                    clean,
                    type(exc).__name__,
                )
                continue
            if issuer and issuer.strip():
                collected.append(issuer.strip())
        if not collected:
            return []
        return _match_patterns(catalog, self.source, collected)

    @staticmethod
    def _scan_default(domain: str) -> str:
        from tools.cert_monitor.data.cert_scanner import (
            CertScanner as _Scanner,  # noqa: PLC0415
        )

        cert = _Scanner().scan(domain)
        return getattr(cert, "aussteller", "") or ""
