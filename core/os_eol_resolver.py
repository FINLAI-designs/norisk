"""
os_eol_resolver — End-of-Life-Status fuer Betriebssysteme.

Iter 2f: Kuratierter Catalog der Windows-Versionen
mit ihren EOL-Daten. Wird vom System-Scanner aufgerufen um eine
EOL-Warnung im OS-Status-Banner anzuzeigen.

Bewusst nur ein in-Memory-Catalog (kein endoflife.date-API-Call) — die
Windows-EOL-Daten aendern sich selten, und der Scanner muss offline
funktionieren. Aktualisierungen erfolgen via Git-PR.

Schichtzugehoerigkeit: ``core/`` — Domain-Service, kein GUI-Import,
keine Datenbank.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Final

from core.logger import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class OsEolEntry:
    """Catalog-Eintrag fuer eine einzelne OS-Version.

    Attributes:
        name: Display-Name (z. B. ``"Windows 10 22H2"``).
        family: OS-Familie (``"windows-client"`` / ``"windows-server"`` /
                    ``"macos"`` / ``"linux"``).
        eol_date: Datum ab dem keine Vendor-Patches mehr (ISO-Date).
        successor: Empfohlene Nachfolge-Version (User-lesbar).
        notes: Optionaler Kontext (z. B. "ESU verfuegbar bis 2028").
    """

    name: str
    family: str
    eol_date: date
    successor: str = ""
    notes: str = ""


@dataclass(frozen=True)
class OsEolStatus:
    """Resolutions-Ergebnis fuer ein konkretes OS.

    Attributes:
        os_name: Eingabe-Name wie vom Scanner geliefert.
        matched_entry: Best-Match aus dem Catalog (``None`` wenn nichts
                         passte — dann ist ``is_eol = False``).
        is_eol: ``True`` wenn ``eol_date <= today``.
        days_until_eol: Negativ wenn schon EOL; positiv wenn noch nicht.
                         ``None`` wenn unbekannt.
        is_expiring_soon: ``True`` wenn EOL in <= 180 Tagen.
    """

    os_name: str
    matched_entry: OsEolEntry | None
    is_eol: bool
    days_until_eol: int | None
    is_expiring_soon: bool

    @property
    def headline(self) -> str:
        """Zeile fuer das OS-Banner — fail-safe Default bei Unbekannt."""
        if self.matched_entry is None:
            return f"{self.os_name}: EOL-Status unbekannt."
        entry = self.matched_entry
        if self.is_eol:
            return (
                f"{entry.name} ist seit {entry.eol_date.isoformat()} "
                "End-of-Life — keine Sicherheits-Patches mehr."
            )
        if self.is_expiring_soon and self.days_until_eol is not None:
            return (
                f"{entry.name} laeuft am {entry.eol_date.isoformat()} aus "
                f"(noch {self.days_until_eol} Tage)."
            )
        return f"{entry.name}: aktuell unterstuetzt (EOL: {entry.eol_date.isoformat()})."


# ---------------------------------------------------------------------------
# Catalog — Windows-Versionen (Stand 2026-05-16)
# Datenquelle: Microsoft Lifecycle-Dokumentation +
# https://endoflife.date/windows
# ---------------------------------------------------------------------------


_CATALOG: Final[tuple[OsEolEntry, ...]] = (
    # ── Windows Client ─────────────────────────────────────────────────
    OsEolEntry(
        name="Windows 7",
        family="windows-client",
        eol_date=date(2020, 1, 14),
        successor="Windows 10/11",
        notes="ESU lief 2023-01-10 endgueltig aus.",
    ),
    OsEolEntry(
        name="Windows 8",
        family="windows-client",
        eol_date=date(2016, 1, 12),
        successor="Windows 10/11",
    ),
    OsEolEntry(
        name="Windows 8.1",
        family="windows-client",
        eol_date=date(2023, 1, 10),
        successor="Windows 10/11",
    ),
    OsEolEntry(
        name="Windows 10",
        family="windows-client",
        eol_date=date(2025, 10, 14),
        successor="Windows 11",
        notes="ESU fuer Consumer kostenpflichtig bis 2026-10-13.",
    ),
    OsEolEntry(
        name="Windows 11",
        family="windows-client",
        eol_date=date(2031, 10, 14),
        successor="Windows 12 (noch nicht angekuendigt)",
        notes="Generisches Familien-EOL — neuere Builds bleiben laenger.",
    ),
    # ── Windows Server ─────────────────────────────────────────────────
    OsEolEntry(
        name="Windows Server 2008 R2",
        family="windows-server",
        eol_date=date(2020, 1, 14),
        successor="Windows Server 2019/2022",
    ),
    OsEolEntry(
        name="Windows Server 2012",
        family="windows-server",
        eol_date=date(2023, 10, 10),
        successor="Windows Server 2019/2022",
    ),
    OsEolEntry(
        name="Windows Server 2012 R2",
        family="windows-server",
        eol_date=date(2023, 10, 10),
        successor="Windows Server 2019/2022",
    ),
    OsEolEntry(
        name="Windows Server 2016",
        family="windows-server",
        eol_date=date(2027, 1, 12),
        successor="Windows Server 2022/2025",
    ),
    OsEolEntry(
        name="Windows Server 2019",
        family="windows-server",
        eol_date=date(2029, 1, 9),
        successor="Windows Server 2025",
    ),
    OsEolEntry(
        name="Windows Server 2022",
        family="windows-server",
        eol_date=date(2031, 10, 14),
        successor="Windows Server 2025",
    ),
)


# Sortier-Reihenfolge: spezifischere Namen zuerst (z. B. "Windows 8.1"
# vor "Windows 8"), damit der Substring-Match nicht beim kuerzeren stoppt.
_CATALOG_BY_NAME_LENGTH: Final[tuple[OsEolEntry, ...]] = tuple(
    sorted(_CATALOG, key=lambda e: -len(e.name))
)


_EXPIRING_SOON_DAYS: Final[int] = 180


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def _normalize(name: str) -> str:
    """Lowercase + Whitespace-Kollaps, fuer robusten Substring-Match."""
    return re.sub(r"\s+", " ", name.strip().lower())


def resolve_os(
    os_name: str, *, today: date | None = None
) -> OsEolStatus:
    """Liefert den EOL-Status fuer einen OS-Namen.

    Match-Strategie: Lowercase-Substring — der Catalog-Eintrag mit dem
    laengsten Namen, der in ``os_name`` enthalten ist, gewinnt. Beispiel:
    ``os_name = "Microsoft Windows 8.1 Pro x64"`` → Match auf
    ``"Windows 8.1"`` (nicht ``"Windows 8"``, weil ``"Windows 8.1"`` zuerst
    in der nach Laenge sortierten Liste steht).

    Args:
        os_name: OS-Bezeichner wie ihn der Scanner liefert
            (z. B. WMI Win32_OperatingSystem.Caption).
        today: Referenz-Datum (Default: ``datetime.now(UTC).date``).
                 Injizierbar fuer Tests.

    Returns:
:class:`OsEolStatus` — bei Non-Match: ``matched_entry=None``,
        ``is_eol=False``, ``days_until_eol=None``.
    """
    if not os_name.strip():
        return OsEolStatus(
            os_name=os_name,
            matched_entry=None,
            is_eol=False,
            days_until_eol=None,
            is_expiring_soon=False,
        )

    today = today or datetime.now(UTC).date()
    needle = _normalize(os_name)
    for entry in _CATALOG_BY_NAME_LENGTH:
        if _normalize(entry.name) in needle:
            days = (entry.eol_date - today).days
            return OsEolStatus(
                os_name=os_name,
                matched_entry=entry,
                is_eol=days < 0,
                days_until_eol=days,
                is_expiring_soon=0 <= days <= _EXPIRING_SOON_DAYS,
            )
    return OsEolStatus(
        os_name=os_name,
        matched_entry=None,
        is_eol=False,
        days_until_eol=None,
        is_expiring_soon=False,
    )


def catalog() -> tuple[OsEolEntry, ...]:
    """Liefert eine read-only-Kopie des OS-EOL-Catalogs."""
    return _CATALOG
