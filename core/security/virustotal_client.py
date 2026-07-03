"""
virustotal_client — Hash-only-Lookup gegen die VirusTotal API v3.

Document Scanner Iter 4: User klickt explizit auf
"VirusTotal pruefen" auf einer ResultCard → wir schicken NUR den
SHA-256-Hash. Die Datei selbst verlaesst nie das Geraet.

API-Key liegt in:class:`SecureStorage` unter dem Eintrag
``virustotal_api_key``. Fehlt der Key, gibt ``lookup_hash`` einen
``VtResult`` mit Status ``key_missing`` zurueck — kein HTTP-Call.

Rate-Limit-Bewusstsein: VT Free-Plan erlaubt 4 Requests/Minute. Wir
machen kein Polling, sondern genau einen Request pro User-Klick. Das
deckt den UX-Fall ab.

Schichtzugehoerigkeit: core/security/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.logger import get_logger

_log = get_logger(__name__)

#: SecureStorage-Schluessel fuer den VT-API-Key.
VT_API_KEY_STORE: str = "virustotal_api_key"

#: VirusTotal API v3 Base-URL.
VT_API_BASE: str = "https://www.virustotal.com/api/v3"

#: Default-Timeout pro VT-Request (Sekunden).
DEFAULT_TIMEOUT: int = 10

VtStatus = Literal["clean", "suspicious", "malicious", "unknown", "key_missing", "error"]


@dataclass(frozen=True)
class VtResult:
    """Antwort eines VT-Hash-Lookups.

    Attributes:
        status: Aggregierte Aussage:
                          - ``"clean"`` — Hash bekannt, 0 malicious.
                          - ``"suspicious"``— >=1 suspicious, 0 malicious.
                          - ``"malicious"`` — >=1 malicious.
                          - ``"unknown"`` — Hash nicht in VT bekannt
                            (HTTP 404).
                          - ``"key_missing"`` — kein API-Key konfiguriert.
                          - ``"error"`` — HTTP-/Lib-Fehler.
        malicious: Anzahl AV-Engines die "malicious" sagen.
        suspicious: Anzahl AV-Engines die "suspicious" sagen.
        harmless: Anzahl AV-Engines die "harmless" sagen.
        undetected: Anzahl AV-Engines die nichts gefunden haben.
        permalink: VT-Permalink zum Hash (User kann manuell prüfen).
        message: User-orientierter Status (Fehlertext bei error).
    """

    status: VtStatus
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    permalink: str = ""
    message: str = ""


def _classify(stats: dict) -> VtStatus:
    """Aggregiert das VT-Stats-Dict in unseren VtStatus."""
    m = int(stats.get("malicious", 0))
    s = int(stats.get("suspicious", 0))
    if m > 0:
        return "malicious"
    if s > 0:
        return "suspicious"
    return "clean"


def _load_api_key() -> str | None:
    """Liest den API-Key aus SecureStorage. ``None`` wenn nicht gesetzt."""
    try:
        from core.security.encryption import get_secure_storage  # noqa: PLC0415

        storage = get_secure_storage()
        if not getattr(storage, "is_available", True):
            return None
        key = storage.get(VT_API_KEY_STORE)
    except Exception as exc:  # noqa: BLE001 -- SecureStorage darf nie crashen
        _log.debug("VT-Key-Load fehlgeschlagen: %s", exc)
        return None
    return key or None


def has_api_key() -> bool:
    """True wenn ein VT-API-Key in SecureStorage liegt."""
    return _load_api_key() is not None


def lookup_hash(sha256: str, *, timeout: int = DEFAULT_TIMEOUT) -> VtResult:
    """Schickt einen einzelnen SHA-256-Hash an VT.

    Args:
        sha256: Hex-String des Hashes (lower- oder uppercase).
        timeout: HTTP-Timeout in Sekunden.

    Returns:
:class:`VtResult` mit Status + Stats. Die Datei selbst wird
        NIE hochgeladen — nur der Hash.
    """
    if not sha256 or len(sha256) != 64:
        return VtResult(status="error", message="Ungueltiger SHA-256-Hash.")

    if not external_fetches_allowed():
        return VtResult(status="error", message=OFFLINE_HINT)

    api_key = _load_api_key()
    if api_key is None:
        return VtResult(
            status="key_missing",
            message=(
                "Kein VirusTotal-API-Key konfiguriert. "
                "In Einstellungen → API-Keys einrichten."
            ),
        )

    try:
        import httpx  # noqa: PLC0415
    except ImportError:
        return VtResult(
            status="error",
            message="HTTP-Client 'httpx' nicht installiert.",
        )

    url = f"{VT_API_BASE}/files/{sha256.lower()}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
    except (httpx.TimeoutException, httpx.NetworkError) as exc:
        _log.warning("VT-Request fehlgeschlagen: %s", type(exc).__name__)
        return VtResult(
            status="error",
            message="VirusTotal nicht erreichbar (Timeout/Netzwerk).",
        )
    except Exception as exc:  # noqa: BLE001 -- httpx kann interne Errors werfen
        _log.warning("VT-Request unerwarteter Fehler: %s", exc)
        return VtResult(status="error", message=f"VT-Fehler: {type(exc).__name__}")

    if resp.status_code == 404:
        return VtResult(
            status="unknown",
            message=(
                "Hash unbekannt bei VirusTotal — kein vorhandenes "
                "Sample. Das ist OK fuer frische Dateien, aber kein "
                "Reinheits-Beweis."
            ),
        )
    if resp.status_code == 401:
        return VtResult(
            status="error",
            message="VT-API-Key abgelehnt (HTTP 401) — bitte erneuern.",
        )
    if resp.status_code == 429:
        return VtResult(
            status="error",
            message=(
                "VT-Rate-Limit erreicht (4 Requests/Minute im Free-Plan). "
                "Bitte spaeter erneut versuchen."
            ),
        )
    if resp.status_code != 200:
        return VtResult(
            status="error",
            message=f"VT antwortet mit HTTP {resp.status_code}.",
        )

    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001
        return VtResult(status="error", message=f"VT-Response nicht parsebar: {exc}")

    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    status = _classify(stats)
    permalink = f"https://www.virustotal.com/gui/file/{sha256.lower()}"

    return VtResult(
        status=status,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
        permalink=permalink,
        message=_message_for(status, stats),
    )


def _message_for(status: VtStatus, stats: dict) -> str:
    m = int(stats.get("malicious", 0))
    s = int(stats.get("suspicious", 0))
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected"))
    if status == "malicious":
        return (
            f"{m} Antivirus-Engine(s) markieren die Datei als boesartig "
            f"(aus {total} Engines)."
        )
    if status == "suspicious":
        return (
            f"{s} Antivirus-Engine(s) markieren die Datei als verdaechtig "
            f"(aus {total} Engines)."
        )
    return f"VirusTotal: 0 Treffer aus {total} Antivirus-Engines."
