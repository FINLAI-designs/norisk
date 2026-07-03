"""core/link_profile_loader.py — Laden von kundenspezifischen Link-Profilen.

Link-Profile sind JSON-Dateien unter configs/link_profiles/<profile_id>.json.
Sie definieren kuratierte Links pro Kunde als Ersatz für die in
``curated_links.py`` hardcodierten Links.

Funktioniert sowohl im Entwicklungs-Modus (Pfade relativ zum Projekt-Root)
als auch im gebündelten Modus (PyInstaller: sys._MEIPASS).

Schichtzugehörigkeit: core/ — kein GUI-Import.

Author: Patrick Riederich
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from core.curated_links import CuratedLink

_log = logging.getLogger("finlai.link_profile_loader")

# Profil-Verzeichnis relativ zum Projekt-Root (dev) bzw. Bundle-Root (frozen)
_PROFILES_SUBPATH = Path("configs") / "link_profiles"


def _profiles_dir() -> Path:
    """Gibt das Verzeichnis mit den Link-Profil-Dateien zurück.

    Im Build-Modus (PyInstaller) wird ``sys._MEIPASS`` als Root verwendet,
    im Entwicklungs-Modus der Projekt-Root (zwei Ebenen über diesem Modul).

    Returns:
        Absoluter Pfad zum Link-Profile-Verzeichnis.
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / _PROFILES_SUBPATH  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent / _PROFILES_SUBPATH


def load_link_profile(profile_id: str) -> list[CuratedLink]:
    """Lädt ein Link-Profil aus der JSON-Datei und konvertiert es zu CuratedLinks.

    Fällt auf ``default.json`` zurück wenn:
    - die angeforderte Profil-Datei nicht existiert
    - die Datei ungültiges JSON enthält
    - die Datei ein unbekanntes Schema hat

    Args:
        profile_id: Profil-Bezeichner, z.B. ``"kunde1"`` oder ``"default"``.

    Returns:
        Liste von CuratedLink-Objekten, nach Gruppen-Reihenfolge und
        Eintrag-Reihenfolge aus der JSON sortiert.
        Leere Liste wenn auch das Default-Profil nicht geladen werden kann.
    """
    path = _profiles_dir() / f"{profile_id}.json"
    if not path.exists():
        if profile_id != "default":
            _log.warning(
                "Link-Profil '%s' nicht gefunden (%s) — Fallback auf default.",
                profile_id,
                path,
            )
            return load_link_profile("default")
        _log.warning("Standard-Link-Profil nicht gefunden: %s", path)
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning(
            "Link-Profil '%s' konnte nicht gelesen werden: %s", profile_id, exc
        )
        if profile_id != "default":
            return load_link_profile("default")
        return []

    return _parse_profile(data)


def _parse_profile(data: dict) -> list[CuratedLink]:
    """Konvertiert ein geparstetes Profil-Dict zu einer CuratedLink-Liste.

    Jede Gruppe (``data["groups"]``) wird als Kategorie verwendet.
    Links innerhalb einer Gruppe behalten ihre Reihenfolge. Gruppen-interne
    sort_order entspricht dem Index (0-basiert, global über alle Gruppen).

    Args:
        data: Geparstetes JSON-Dict des Link-Profils.

    Returns:
        Flache Liste von CuratedLink-Objekten.
    """
    groups: list[dict] = data.get("groups", [])
    result: list[CuratedLink] = []
    global_order = 0
    for grp in groups:
        category = grp.get("label", "Links")
        for entry in grp.get("links", []):
            result.append(
                CuratedLink(
                    title=entry.get("label", ""),
                    url=entry.get("url", ""),
                    category=category,
                    icon=entry.get("icon", "link"),
                    description=entry.get("description", ""),
                    sort_order=global_order,
                )
            )
            global_order += 1
    return result


def list_available_profiles() -> list[str]:
    """Gibt die IDs aller verfügbaren Link-Profile zurück.

    Returns:
        Alphabetisch sortierte Liste von Profil-IDs (ohne ``.json``-Endung).
    """
    profiles_dir = _profiles_dir()
    if not profiles_dir.exists():
        return []
    return sorted(p.stem for p in profiles_dir.glob("*.json"))
