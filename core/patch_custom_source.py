"""patch_custom_source — Manuell gepflegte Patch-Quelle.

Eine:class:`CustomSource` ist eine App, die NICHT ueber winget/msstore
verwaltet wird. Der Patch-Monitor liest ihren Versionsstand per HTTP-GET von
einer Vendor-Website (Variante A — **Notify-Only**: kein Auto-Download, kein
Auto-Install).

Schichtzugehoerigkeit: ``core/`` (Shared Domain — genutzt von
``tools/patch_monitor`` in data/application/gui, analog
:mod:`core.patch_strategy` /:mod:`core.patch_result`). Reine Daten, keine I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final


class Platform(StrEnum):
    """Betriebssystem-Plattform einer Custom-Source.

    Als:class:`enum.StrEnum` ist jedes Mitglied sein eigener DB-/UI-String
    (``Platform.WINDOWS == "win"``) — Persistenz ohne separates Mapping.
    """

    WINDOWS = "win"
    MACOS = "mac"
    LINUX = "linux"


#: Default-Plattform fuer neue Custom-Sources (NoRisk ist Windows-zentriert).
DEFAULT_PLATFORM: Final[Platform] = Platform.WINDOWS


@dataclass(frozen=True)
class CustomSource:
    """Manuell gepflegte Patch-Quelle (Notify-Only).

    Attributes:
        id: UUID4-Hex, vom Repository vergeben.
        name: Anzeigename der App (z. B. ``"Mein Vendor-Tool"``).
        vendor_url: URL, von der der Versionsstand gelesen wird. Wird dem
            User in der UI VOLL angezeigt (Phishing-Lookalike-Schutz).
        version_regex: Regex, der die Version aus der Seite extrahiert
            (erste Capture-Gruppe = Version). Stop-Step B wertet ihn aus.
        platform: Ziel-Plattform (:class:`Platform`).
        installed_version: Vom User gepflegte aktuell installierte Version
            (Vergleichsbasis). ``None`` wenn noch nicht gesetzt.
        available_version: Zuletzt von ``vendor_url`` gelesene Version.
            ``None`` bis zum ersten erfolgreichen Check (Stop-Step B).
        last_checked_at: Zeitpunkt des letzten Check-Versuchs. ``None`` bis
            zum ersten Check.
        last_error: Fehlertext des letzten Checks (z. B. ``"Quelle nicht
            lesbar"`` bei Markup-Bruch), sonst ``None``.
        notes: Freitext-Notiz des Users (optional).
        created_at: Anlage-Zeitpunkt.
    """

    id: str
    name: str
    vendor_url: str
    version_regex: str
    platform: Platform
    installed_version: str | None
    available_version: str | None
    last_checked_at: datetime | None
    last_error: str | None
    notes: str | None
    created_at: datetime
