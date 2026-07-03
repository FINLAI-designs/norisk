"""
feed_settings — Persistente Ein/Aus-Schalter für Consumer-Security-Feeds.

Liegt separat von:mod:`core.ui_settings`, weil das dortige dataclass-Schema
starr ist und ein Migrations-Durchlauf sich nicht lohnt. Die Datei wird
lazy beim ersten Zugriff erzeugt.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

FEED_SETTINGS_PATH = finlai_dir() / "feed_settings.json"

#: Einheitlicher Hinweis-Text, wenn ein externer Abruf im Offline-Modus
#: uebersprungen wird. Tools zeigen ihn in ihrem bestehenden
#: Status-/Fehlerkanal an, statt still ins Leere zu laufen.
OFFLINE_HINT = "Externe Abrufe deaktiviert (Einstellungen)"

# Reihenfolge = Anzeige-Reihenfolge im Settings-Tab.
# ``watchlist_at`` ergaenzt — Watchlist Internet
# (OIAT, Phishing-/Betrugs-Warnungen) ist seit als RSS-Quelle
# im Cyber-Dashboard integriert und darf user-seitig zu-/abschaltbar
# sein. ``cert_at`` und ``the_hacker_news`` werden im
# ``rss_service`` immer geladen — gehoeren deshalb nicht in den
# Consumer-Schalter (sie sind System-Feeds, nicht User-Wahl).
_DEFAULT_CONSUMER_FEEDS: list[str] = [
    "bsi",
    "msrc",
    "chrome",
    "mozilla",
    "watchlist_at",
]

#: Erlaubte Werte fuer ``FeedSettings.phishing_ebene`` (c1, 2026-06-26). Steuert,
#: welche Phishing-Gruppen die Briefing-Sektion anzeigt. Default ``beide`` —
#: beide Ebenen sind fuer KMU-Inhaber relevant (privat + geschaeftlich).
PHISHING_EBENEN: tuple[str, ...] = ("beide", "kmu", "consumer")
_DEFAULT_PHISHING_EBENE = "beide"


@dataclass
class FeedSettings:
    """Schalter für die Consumer-Security-Feeds.

    Attributes:
        consumer_feeds: Dict ``{feed_key: enabled}``. Keys:data:`_DEFAULT_CONSUMER_FEEDS`. Default: alle aktiv.
    """

    consumer_feeds: dict[str, bool] = field(
        default_factory=lambda: {k: True for k in _DEFAULT_CONSUMER_FEEDS}
    )
    #: Master-Schalter fuer ALLE automatischen externen Sicherheits-Abrufe
    #: (Cyber-Lagebild-Feeds, CVE-/KEV-/NVD-/CSAF-Auto-Abruf, HIBP-Leak-Abgleich).
    #: Default True. False = Offline-Modus: keine automatischen Abrufe -> die
    #: Schutzfunktionen (aktuelle Bedrohungen/CVEs/Leak-Abgleich) entfallen weitgehend.
    external_fetches_enabled: bool = True
    #: Welche Phishing-Gruppen das Risikobriefing zeigt (c1):
    #: ``beide`` (Default) | ``kmu`` | ``consumer``. Beide Ebenen sind fuer
    #: KMU-Inhaber relevant -> Default zeigt beide; der Inline-Toggle in der
    #: Briefing-Sektion (briefing_tab) schreibt diesen Wert.
    phishing_ebene: str = _DEFAULT_PHISHING_EBENE

    def to_dict(self) -> dict:
        """Serialisiert fuer JSON-Persistenz."""
        return {
            "consumer_feeds": dict(self.consumer_feeds),
            "external_fetches_enabled": self.external_fetches_enabled,
            "phishing_ebene": self.phishing_ebene,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FeedSettings:
        """Baut eine Instanz aus einem Dict, mit Default-Ergaenzung.

        Neue Feed-Keys (z. B. ``watchlist_at`` ab 2026-05-14) werden
        Default-True erganzt, alte gespeicherte Werte ueberschreiben
        den Default — Migration ohne JSON-Edit.
        """
        stored = data.get("consumer_feeds", {}) if isinstance(data, dict) else {}
        merged = {k: True for k in _DEFAULT_CONSUMER_FEEDS}
        for key, val in stored.items():
            if key in merged and isinstance(val, bool):
                merged[key] = val
        ext = data.get("external_fetches_enabled", True) if isinstance(data, dict) else True
        ebene = (
            data.get("phishing_ebene", _DEFAULT_PHISHING_EBENE)
            if isinstance(data, dict)
            else _DEFAULT_PHISHING_EBENE
        )
        if ebene not in PHISHING_EBENEN:  # ungueltig/alt -> Default
            ebene = _DEFAULT_PHISHING_EBENE
        return cls(
            consumer_feeds=merged,
            external_fetches_enabled=bool(ext),
            phishing_ebene=ebene,
        )


def load_feed_settings(path: Path | None = None) -> FeedSettings:
    """Lädt Feed-Settings vom Standardpfad.

    Args:
        path: Optionaler Pfad (fuer Tests). Default: ``FEED_SETTINGS_PATH``.

    Returns:
:class:`FeedSettings` — bei Lese-/Parse-Fehler das Default.
    """
    target = path or FEED_SETTINGS_PATH
    if not target.exists():
        return FeedSettings()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return FeedSettings.from_dict(data)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        log.warning("feed_settings.json konnte nicht gelesen werden: %s", exc)
        return FeedSettings()


def save_feed_settings(
    settings: FeedSettings,
    path: Path | None = None,
) -> None:
    """Schreibt Feed-Settings als UTF-8-JSON.

    Args:
        settings: Zu speicherndes Settings-Objekt.
        path: Optionaler Pfad (fuer Tests).

    Raises:
        OSError: Bei Schreibfehlern (wird an den Aufrufer durchgereicht).
    """
    target = path or FEED_SETTINGS_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(settings.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def external_fetches_allowed(path: Path | None = None) -> bool:
    """True, wenn automatische externe Sicherheits-Abrufe erlaubt sind (Default).

    Zentrale Pruefung fuer alle AUTOMATISCHEN/Default-an-Netzabrufe (Cyber-
    Lagebild-Feeds, CVE-/KEV-/NVD-/CSAF-Auto-Abruf, HIBP-Leak-Abgleich). Ist der
    Master-Schalter aus (Offline-Modus), ueberspringen die Aufrufer den
    Netzwerkpfad — keine ungefragten externen Abrufe.

    Args:
        path: Optionaler Pfad (fuer Tests). Default: ``FEED_SETTINGS_PATH``.
    """
    return load_feed_settings(path).external_fetches_enabled
