"""network_monitor.application.threat_feed_service — Feed-Orchestrierung F-D).

Use-Case-Schicht über dem Feed-Client, dem verschlüsselten Cache, der lokalen
``blocklist.txt`` und der ``whitelist.txt``. Verantwortlich für:

  -:meth:`update` — Feeds bei abgelaufener TTL über den gehärteten HTTP-Client
    neu laden und in den verschlüsselten Cache schreiben (fail-soft).
  -:meth:`build_entries` /:meth:`build_checker` — lokale Blocklist + gecachte
    Feeds zu einem:class:`ThreatChecker` zusammenführen (Whitelist als Override).
  -:meth:`abuseipdb_lookup` — **optionaler**, opt-in AbuseIPDB-Pfad (User-API-Key
    via:class:`SecureStorage`). Sendet eine IP an einen Dritt-Dienst und ist
    daher consent-pflichtig; standardmäßig deaktiviert. Hinweis: der AbuseIPDB-
    Free-Plan ist für kommerzielle Nutzung untersagt (:data:`ABUSEIPDB_FREE_PLAN_HINWEIS`).

Schichtzugehörigkeit: ``application/`` — orchestriert ``data/`` + ``core`` ohne
GUI-Bezug.

Author: Patrick Riederich
Version: 1.0 F-D)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final

import requests

from core.feed_settings import external_fetches_allowed
from core.http_client import RateLimitExceeded, get_http_client
from core.logger import get_logger
from tools.network_monitor.application.threat_checker import ThreatChecker
from tools.network_monitor.data.blocklist_loader import load_blocklist, load_whitelist
from tools.network_monitor.data.threat_feed_cache import ThreatFeedCacheRepository
from tools.network_monitor.data.threat_feed_client import (
    DEFAULT_SOURCES,
    ThreatFeedClient,
    parse_feed_text,
)
from tools.network_monitor.domain.models import (
    FeedRefreshSnapshot,
    FeedUpdateResult,
    Network,
    ThreatFeedSource,
)

_log = get_logger(__name__)

#: Standard-TTL eines Cache-Eintrags (12 h). Innerhalb der TTL wird nicht erneut
#: geladen — abuse.ch-Feeds aktualisieren im Tages-Takt, häufigeres Pollen wäre
#: unhöflich und brächte keinen Mehrwert.
DEFAULT_TTL_SECONDS: Final[float] = 12 * 3600.0

#: SecureStorage-Schlüssel für den optionalen AbuseIPDB-API-Key.
ABUSEIPDB_KEY_NAME: Final[str] = "abuseipdb_api_key"
_ABUSEIPDB_URL: Final[str] = "https://api.abuseipdb.com/api/v2/check"
#: Schwelle (0–100), ab der AbuseIPDB eine IP als verdächtig gilt.
_ABUSEIPDB_SCORE_THRESHOLD: Final[int] = 50
_ABUSEIPDB_TIMEOUT: Final[int] = 10

#: Pflicht-Hinweis für die UI: AbuseIPDB-Free ist kommerziell untersagt.
ABUSEIPDB_FREE_PLAN_HINWEIS: Final[str] = (
    "AbuseIPDB ist optional und benötigt einen eigenen API-Key. Der kostenlose "
    "AbuseIPDB-Plan ist für die kommerzielle Nutzung untersagt — verwenden Sie "
    "ihn nur privat oder mit einem kostenpflichtigen Plan."
)


class ThreatFeedService:
    """Orchestriert Download, Cache und Zusammenführung der Threat-Intel-Feeds."""

    def __init__(
        self,
        *,
        client: ThreatFeedClient | None = None,
        cache: ThreatFeedCacheRepository | None = None,
        sources: tuple[ThreatFeedSource, ...] = DEFAULT_SOURCES,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        blocklist_path: Path | None = None,
        whitelist_path: Path | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            client: Feed-Client (Default: frischer:class:`ThreatFeedClient`).
            cache: Cache-Repository (Default: frisches Repo — benötigt KeyManager).
            sources: Zu verwaltende Quellen (Default: abuse.ch CC0).
            ttl_seconds: Cache-TTL; innerhalb wird nicht neu geladen.
            blocklist_path: Optionaler Pfad zur lokalen Blocklist (Tests).
            whitelist_path: Optionaler Pfad zur Whitelist (Tests).
        """
        self._client = client or ThreatFeedClient()
        self._cache = cache or ThreatFeedCacheRepository()
        self._sources = sources
        self._ttl = ttl_seconds
        self._blocklist_path = blocklist_path
        self._whitelist_path = whitelist_path

    # ── Update (Download → Cache) ──────────────────────────────────────────

    def update(self, *, force: bool = False) -> FeedUpdateResult:
        """Aktualisiert abgelaufene Quellen aus dem Netz in den Cache (fail-soft).

        Pro aktiver Quelle: ist der Cache jünger als die TTL (und ``force`` aus),
        wird übersprungen; sonst lädt der Client neu. Erfolge landen im Cache,
        Fehler sammeln sich in:attr:`FeedUpdateResult.errors` — ein Quellen-
        Ausfall lässt die übrigen unberührt und der alte Cache bleibt erhalten.

        Args:
            force: Lädt alle aktiven Quellen unabhängig von der TTL neu.

        Returns:
:class:`FeedUpdateResult` mit Aktualisierungs-/Skip-/Fehler-Bilanz.
        """
        updated: list[str] = []
        skipped: list[str] = []
        errors: list[tuple[str, str]] = []

        # Perf (Triage P0a): EINMAL alle Cache-Staende laden statt pro Quelle
        # ein load — jede EncryptedDatabase.connection zahlt die SQLCipher-
        # PBKDF2-Schluesselableitung; das war der Haupttreiber des Refresh-
        # Freezes.
        cached = {c.key: c for c in self._cache.load_all()}
        now = time.time()
        to_save: list[tuple[str, str, int]] = []

        for source in self._sources:
            if not source.enabled:
                continue
            entry = cached.get(source.key)
            is_stale = force or entry is None or (now - entry.fetched_at) >= self._ttl
            if not is_stale:
                skipped.append(source.key)
                continue
            result = self._client.fetch(source)
            if not result.ok:
                errors.append((source.key, result.error or "Abruf fehlgeschlagen"))
                continue
            to_save.append((source.key, result.raw_payload, len(result.entries)))
            updated.append(source.key)

        # Perf (P0a): alle Updates in EINER Verbindung (Bulk-Upsert).
        self._cache.save_many(to_save)

        # Gesamtzahl aus dem In-Memory-Stand (kein zweites load_all noetig).
        final_counts: dict[str, int] = {c.key: c.entry_count for c in cached.values()}
        for key, _payload, count in to_save:
            final_counts[key] = count
        total = sum(final_counts.values())
        _log.info(
            "Feed-Update: %d aktualisiert, %d übersprungen, %d Fehler, %d Einträge gesamt.",
            len(updated),
            len(skipped),
            len(errors),
            total,
        )
        return FeedUpdateResult(
            updated_keys=updated,
            skipped_keys=skipped,
            total_entries=total,
            errors=errors,
        )

    def _is_stale(self, source_key: str) -> bool:
        """``True`` wenn die Quelle fehlt oder älter als die TTL ist."""
        age = self._cache.age_seconds(source_key)
        return age is None or age >= self._ttl

    # ── Build (Cache + lokal → Checker) ────────────────────────────────────

    def build_entries(self) -> list[tuple[Network, str]]:
        """Führt lokale Blocklist + gecachte Feeds zu deduplizierten Einträgen zusammen.

        Reihenfolge: lokale ``blocklist.txt`` zuerst (ihre Begründung gewinnt bei
        Dubletten), danach die gecachten Feeds. Dedup über die Netz-Stringform.

        Returns:
            Zusammengeführte (Netzwerk, Grund)-Liste.
        """
        merged: list[tuple[Network, str]] = list(load_blocklist(self._blocklist_path))
        for cached in self._cache.load_all():
            reason = self._reason_for(cached.key)
            merged.extend(parse_feed_text(cached.raw_payload, reason))

        seen: set[str] = set()
        deduped: list[tuple[Network, str]] = []
        for network, reason in merged:
            net_key = str(network)
            if net_key in seen:
                continue
            seen.add(net_key)
            deduped.append((network, reason))
        return deduped

    def load_whitelist_networks(self) -> list[Network]:
        """Lädt die manuelle Whitelist (Override gegen Treffer)."""
        return load_whitelist(self._whitelist_path)

    def build_checker(self) -> ThreatChecker:
        """Baut einen:class:`ThreatChecker` aus Blocklist + Feeds + Whitelist."""
        return ThreatChecker(
            entries=self.build_entries(),
            whitelist=self.load_whitelist_networks(),
        )

    def refresh_snapshot(self, *, force: bool = False) -> FeedRefreshSnapshot:
        """Ein vollständiger Refresh-Durchlauf: Update → Merge → Whitelist DRY).

        Bündelt die Schritte, die der periodische ``ThreatFeedRefreshWorker`` und der
        manuelle ``ThreatFeedRefreshOnceWorker`` teilen::meth:`update` lädt abgelaufene
        (bzw. bei ``force`` alle) Quellen, danach werden die Einträge neu
        zusammengeführt und die Whitelist gelesen — so liegt die Orchestrierung an
        EINER Stelle statt dupliziert pro Worker.

        Args:
            force: Lädt alle aktiven Quellen unabhängig von der TTL neu (manueller
                Refresh); ``False`` respektiert die TTL (periodischer Lauf).

        Returns:
:class:`FeedRefreshSnapshot` mit Einträgen, Whitelist und Quellen-Bilanz.
        """
        result = self.update(force=force)
        return FeedRefreshSnapshot(
            entries=self.build_entries(),
            whitelist=self.load_whitelist_networks(),
            updated_count=len(result.updated_keys),
            error_count=len(result.errors),
        )

    def _reason_for(self, source_key: str) -> str:
        """Match-Begründung für eine Quelle (Fallback: generisch)."""
        for source in self._sources:
            if source.key == source_key:
                return source.reason
        return "Threat-Intel-Feed"

    # ── AbuseIPDB (optional, opt-in, consent-pflichtig) ────────────────────

    def abuseipdb_available(self) -> bool:
        """``True`` wenn ein AbuseIPDB-API-Key in SecureStorage hinterlegt ist."""
        return bool(self._load_abuseipdb_key())

    def abuseipdb_lookup(self, ip: str, *, consent: bool) -> tuple[bool, str]:
        """Fragt AbuseIPDB zu einer IP — **nur** mit Key UND explizitem Consent.

        Dieser Pfad sendet die IP an einen Dritt-Dienst (AbuseIPDB) und ist daher
        bewusst opt-in: ohne ``consent=True`` oder ohne hinterlegten API-Key
        passiert nichts (``(False, "")``). Er ist NICHT in den Live-Monitor-Pfad
        verdrahtet — der Default bleibt der lokale, datensparsame abuse.ch-Bulk-
        Download.

        Args:
            ip: Zu prüfende IP-Adresse.
            consent: Muss explizit ``True`` sein (der Nutzer hat dem Versand an
                AbuseIPDB zugestimmt).

        Returns:
            (verdächtig, Grund). Bei fehlendem Consent/Key oder Fehler ``(False, "")``.
        """
        if not consent:
            return (False, "")
        if not external_fetches_allowed():
            return (False, "")
        api_key = self._load_abuseipdb_key()
        if not api_key:
            return (False, "")
        try:
            response = get_http_client().get(
                _ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                api_key_header=api_key,
                timeout=_ABUSEIPDB_TIMEOUT,
            )
            data = response.json().get("data", {})
        except (requests.RequestException, RateLimitExceeded, ValueError) as exc:
            _log.warning("AbuseIPDB-Abfrage fehlgeschlagen: %s", type(exc).__name__)
            return (False, "")

        score = int(data.get("abuseConfidenceScore", 0) or 0)
        if score >= _ABUSEIPDB_SCORE_THRESHOLD:
            return (True, f"AbuseIPDB Score {score}/100")
        return (False, "")

    def _load_abuseipdb_key(self) -> str | None:
        """Lädt den AbuseIPDB-Key aus SecureStorage (lazy import, fail-soft)."""
        try:
            from core.security.encryption import (  # noqa: PLC0415
                get_secure_storage,
            )

            return get_secure_storage().get(ABUSEIPDB_KEY_NAME)
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            _log.debug("AbuseIPDB-Key nicht ladbar: %s", type(exc).__name__)
            return None
