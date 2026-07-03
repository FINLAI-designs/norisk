"""custom_source_checker — prueft den Versionsstand einer CustomSource.

Variante A (**Notify-Only**): liest die Vendor-Website per HTTP-GET, extrahiert
die Version per Regex und vergleicht sie mit der user-gepflegten
``installed_version``. **Kein** Auto-Download, **kein** Auto-Install — arbitrary
URLs sind ein Supply-Chain-Risiko ohne Trust-Anchor (kein Code-Signing-Pin,
kein bekannter Hash).

Sicherheit / Privacy:
* HTTP via:func:`core.http_client.get_http_client` (SSL fest an, Rate-Limit
  pro Domain, nur die Domain wird geloggt — nie die volle URL).
* Nur ``http``/``https`` werden akzeptiert (kein ``file://`` o. ae.).
* **Privacy:** Der GET leakt die NoRisk-Nutzung an den Vendor — die UI weist
  beim Anlegen darauf hin (Stop-Step C).
* Markup-Bruch / Fetch-Fehler fuehren zu ``last_error`` ("Quelle nicht
  lesbar"), nie zu einem stillen Fehler.
* Der ``version_regex`` ist user-eigen (User-Trust-Modell) — ein
  pathologischer Regex belastet nur den eigenen Check-Worker.

Schichtzugehoerigkeit: ``application/`` — orchestriert ``core/``-HTTP +
``core.patch_custom_source``-Domain. Kein GUI, kein direkter DB-Zugriff: die
Persistenz des Ergebnisses erfolgt beim Caller via
``PatchInventoryRepository.update_custom_source``. Headless-testbar
(``fetch``-Injection).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlparse

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.http_client import get_http_client
from core.logger import get_logger
from core.patch_custom_source import CustomSource

log = get_logger(__name__)

#: Timeout fuer den Vendor-GET in Sekunden.
DEFAULT_FETCH_TIMEOUT_S: Final[int] = 15

#: Soft-Limit fuer den ausgewerteten Seiteninhalt (DoS-/ReDoS-Schutz). Der
#: ``core.http_client`` streamt nicht — wir kappen den Text vor dem Regex.
_MAX_BODY_CHARS: Final[int] = 2_000_000

#: User-lesbare Fehlertexte (Sie-Form, deutsch) fuer ``last_error``.
ERR_INVALID_REGEX: Final[str] = "Ungueltiger Versions-Regex"
ERR_NON_HTTP: Final[str] = "Quelle nicht lesbar — nur http/https erlaubt"
ERR_UNREACHABLE: Final[str] = "Quelle nicht erreichbar"
ERR_VERSION_NOT_FOUND: Final[str] = "Quelle nicht lesbar — Version nicht gefunden"


def _is_http_url(url: str) -> bool:
    """``True`` wenn ``url`` ein ``http``/``https``-Schema + Host hat."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_update_available(source: CustomSource) -> bool:
    """``True`` wenn eine abweichende Version gelesen wurde.

    Notify-Only-Semantik: jede Abweichung von der user-gepflegten
    ``installed_version`` gilt als "Update verfuegbar" (String-Vergleich,
    kein Semver — der User pflegt beide Werte). Ohne ``available_version``
    oder bei letztem Fehler → ``False``.
    """
    if source.last_error is not None:
        return False
    if source.available_version is None or source.installed_version is None:
        return False
    return source.available_version != source.installed_version


class CustomSourceChecker:
    """Liest + vergleicht den Versionsstand einer:class:`CustomSource`.

    Beispiel::

        checker = CustomSourceChecker
        updated = checker.check(source) # neue available_version / Fehler
        repo.update_custom_source(updated) # Persistenz beim Caller
    """

    def __init__(
        self,
        *,
        fetch: Callable[[str], str] | None = None,
        timeout_s: int = DEFAULT_FETCH_TIMEOUT_S,
    ) -> None:
        """Initialisiert den Checker.

        Args:
            fetch: Optionale Fetch-Funktion ``(url) -> body``. Standard nutzt
:func:`core.http_client.get_http_client`. Tests injizieren ein
                Surrogat (kein echter HTTP-Call).
            timeout_s: Timeout fuer den Default-Fetch.
        """
        self._fetch = fetch or self._default_fetch
        self._timeout_s = timeout_s

    def check(self, source: CustomSource) -> CustomSource:
        """Prueft ``source`` und gibt eine aktualisierte Kopie zurueck.

        Setzt immer ``last_checked_at`` auf jetzt. Bei Erfolg:
        ``available_version`` = gelesene Version, ``last_error`` = ``None``.
        Bei Fehler bleibt die letzte ``available_version`` erhalten und
        ``last_error`` traegt den Grund. Wirft keine Exception (Batch-tauglich).

        Args:
            source: Die zu pruefende Custom-Source.

        Returns:
            Aktualisierte:class:`CustomSource` (frozen — neue Instanz).
        """
        now = datetime.now(tz=UTC)

        if not external_fetches_allowed():
            return replace(source, last_checked_at=now, last_error=OFFLINE_HINT)

        try:
            pattern = re.compile(source.version_regex)
        except re.error:
            return replace(source, last_checked_at=now, last_error=ERR_INVALID_REGEX)

        if not _is_http_url(source.vendor_url):
            return replace(source, last_checked_at=now, last_error=ERR_NON_HTTP)

        try:
            body = self._fetch(source.vendor_url)
        except Exception as exc:  # noqa: BLE001 — jeder Fetch-Fehler → Notify-Status
            log.warning(
                "custom_source check fehlgeschlagen (%s): %s",
                source.name,
                type(exc).__name__,
            )
            return replace(source, last_checked_at=now, last_error=ERR_UNREACHABLE)

        match = pattern.search(body[:_MAX_BODY_CHARS])
        if match is None:
            return replace(
                source, last_checked_at=now, last_error=ERR_VERSION_NOT_FOUND
            )

        version = (match.group(1) if match.groups() else match.group(0)).strip()
        return replace(
            source,
            available_version=version,
            last_checked_at=now,
            last_error=None,
        )

    def _default_fetch(self, url: str) -> str:
        """Default-Fetch ueber den zentralen FINLAI-HTTP-Client."""
        response = get_http_client().get(url, timeout=self._timeout_s)
        return response.text
