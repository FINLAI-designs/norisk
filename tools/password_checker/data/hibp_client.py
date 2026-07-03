"""hibp_client — Have I Been Pwned Passwort-Check (k-Anonymity).

Prüft ob ein Passwort in bekannten Datenpannen vorkommt.

Datenschutz-Mechanismus (k-Anonymity):
    1. SHA-1-Hash des Passworts berechnen (lokal)
    2. Nur die ersten 5 Hex-Zeichen des Hashes an HIBP senden
    3. HIBP gibt alle ~500 Hashes mit diesem Prefix zurück
    4. Lokal prüfen ob der vollständige Hash dabei ist

Das Passwort verlässt niemals den Computer — DSGVO-konform.

Referenz: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

Schichtzugehörigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import hashlib

from core.http_client import get_http_client
from core.logger import get_logger

_log = get_logger(__name__)

_HIBP_BASE_URL = "https://api.pwnedpasswords.com/range/"
_REQUEST_TIMEOUT = 8  # Sekunden


class HIBPClient:
    """Client für die Have I Been Pwned Passwort-Range-API.

    Nutzt k-Anonymity: Das Passwort wird lokal gehashed, nur der
    5-Zeichen-Prefix des SHA-1-Hashes geht an die API.
    """

    def __init__(self) -> None:
        self._http = get_http_client()

    def ist_kompromittiert(self, passwort: str) -> tuple[bool, int]:
        """Prüft ob das Passwort in bekannten Datenpannen vorkommt.

        Das Passwort wird lokal gehashed — nur der Hash-Prefix wird übertragen.

        Args:
            passwort: Das zu prüfende Passwort (verlässt nie den Computer).

        Returns:
            Tuple (kompromittiert, anzahl_vorkommen).
            Bei Verbindungsfehler: (False, 0) — kein Alarm bei Netzwerkproblemen.
        """
        sha1 = (
            hashlib.sha1(passwort.encode("utf-8"), usedforsecurity=False)
            .hexdigest()
            .upper()
        )
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            response = self._http.get(
                f"{_HIBP_BASE_URL}{prefix}",
                timeout=_REQUEST_TIMEOUT,
            )
            response.raise_for_status()

            for line in response.text.splitlines():
                if ":" not in line:
                    continue
                hash_suffix, count_str = line.split(":", 1)
                if hash_suffix.strip() == suffix:
                    vorkommnisse = int(count_str.strip())
                    _log.info(
                        "HIBP: Passwort-Hash in %d Datenpannen gefunden", vorkommnisse
                    )
                    return True, vorkommnisse

            return False, 0

        except Exception:  # noqa: BLE001
            _log.warning("HIBP-Prüfung nicht verfügbar — Netzwerkfehler")
            return False, 0
