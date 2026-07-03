"""
changelog_parser — Parser für CHANGELOG.md → ChangelogEntry-Liste.

Parst CHANGELOG.md dynamisch bei jedem Aufruf — keine DB-Speicherung.
Dadurch immer aktuell.

Unterstützte Formate:
    ## [1.0.0] - 2026-01-15
    ## [1.0.0] — 2026-01-15 (langer Gedankenstrich)
    ## [Unreleased]

    ### Hinzugefügt / Added
    ### Geändert / Changed
    ### Behoben / Fixed
    ### Sicherheit / Security

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import re
from pathlib import Path

from core.logger import get_logger
from tools.mainpage.domain.models import ChangelogEntry

logger = get_logger(__name__)


class ChangelogParser:
    """Parst CHANGELOG.md dynamisch.

    Liest die Datei bei jedem Aufruf neu — keine DB-Speicherung.
    Dadurch immer aktuell.

    Attributes:
        CHANGELOG_PATH: Pfad zur CHANGELOG.md-Datei.
    """

    CHANGELOG_PATH = Path("docs/CHANGELOG.md")

    def parse(self, max_versions: int = 3) -> list[ChangelogEntry]:
        """Parst CHANGELOG.md.

        Args:
            max_versions: Maximale Anzahl zurückzugebender Versionen.

        Returns:
            Liste der neuesten Versionen. Gibt ``[_placeholder]`` zurück
            wenn die Datei nicht existiert.
        """
        if not self.CHANGELOG_PATH.exists():
            return [self._placeholder()]

        text = self.CHANGELOG_PATH.read_text(encoding="utf-8")

        entries: list[ChangelogEntry] = []
        current: ChangelogEntry | None = None
        current_section: str | None = None

        for line in text.splitlines():
            # Version-Header: ## [1.0.0] — 2026-03-17 oder ## [Unreleased]
            ver_match = re.match(
                r"^## \[(.+?)\](?:\s*[-\u2014]\s*(\d{4}-\d{2}-\d{2}))?",
                line,
            )
            if ver_match:
                if current:
                    entries.append(current)
                    if len(entries) >= max_versions:
                        break
                current = ChangelogEntry(
                    version=ver_match.group(1),
                    date=ver_match.group(2) or "",
                )
                current_section = None
                continue

            if current is None:
                continue

            # Abschnitt erkennen (Deutsch + Englisch)
            if line.startswith("### "):
                sec = line[4:].lower()
                if "hinzugefügt" in sec or "added" in sec:
                    current_section = "added"
                elif "geändert" in sec or "changed" in sec:
                    current_section = "changed"
                elif "behoben" in sec or "fixed" in sec:
                    current_section = "fixed"
                elif "sicherheit" in sec or "security" in sec:
                    current_section = "security"
                else:
                    current_section = None
                continue

            # Listen-Eintrag
            if line.startswith("- ") and current_section:
                item = line[2:].strip()
                getattr(current, current_section).append(item)

        if current and len(entries) < max_versions:
            entries.append(current)

        return entries

    def _placeholder(self) -> ChangelogEntry:
        """Gibt einen Platzhalter-Eintrag zurück wenn CHANGELOG.md fehlt."""
        return ChangelogEntry(
            version="1.0.0",
            date="",
            added=["FINLAI gestartet!"],
        )
