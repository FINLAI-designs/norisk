"""
guide_registry — kuratierte FINLAI-Leitfaden-PDFs fuer die "FINLAI empfiehlt"-
Anleitung (c2, 2026-06-26).

Die PDFs sind die sauberen ALLGEMEIN-Fassungen der Marketing-VWAs (Quelle:
interne Doku-Builds), ins App-Repo gebuendelt unter
``resources/guides/`` (Spec: build_norisk.spec). Der Cockpit-Anleitungs-Dialog
bietet den passenden Leitfaden zum Oeffnen an (``QDesktopServices`` in der gui-
Schicht) — NoRisk bleibt 100% lokal, kein Netz noetig.

Liegt in core/ (wie ``core.curated_links``), weil die "FINLAI empfiehlt"-Sektion
(``KiTodoSection``) sowohl auf der Mainpage als auch im Cockpit erscheint — ein
gemeinsames Zuhause vermeidet Cross-Tool-Kopplung.

Schichtzugehoerigkeit: core/ — Pfad-Aufloesung + Schlagwort-Matching, kein
GUI-/DB-Import. Das Oeffnen (Qt) macht die gui-Schicht mit ``guide_path``.

Author: Patrick Riederich
Version: 1.0 (c2)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final


@dataclass(frozen=True)
class GuideEntry:
    """Ein kuratierter Leitfaden.

    Attributes:
        key: Stabiler Schluessel (z. B. ``"backup_321"``).
        title: Anzeigename im Anleitungs-Dialog.
        filename: Dateiname unter ``resources/guides/``.
        schlagworte: Lowercase-Substrings; matcht der Befund-Text einen davon,
            ist der Leitfaden relevant. Effekt: ``match_guides`` ordnet einem
            "FINLAI empfiehlt"-Todo den passenden Leitfaden zu — Aenderung hier
            aendert, welcher Guide bei welchem Befund vorgeschlagen wird.
    """

    key: str
    title: str
    filename: str
    schlagworte: tuple[str, ...] = field(default_factory=tuple)


#: Verzeichnis der gebuendelten Leitfaden-PDFs relativ zum Bundle/Repo-Root.
_GUIDES_SUBPATH: Final = Path("resources") / "guides"

#: Schluessel des allgemeinen Fallback-Leitfadens (wenn kein Thema matcht).
_FALLBACK_KEY: Final = "grundschutz_kmu"

#: Kuratierte Leitfaden-Bibliothek. Reihenfolge = Vorschlags-Prioritaet.
_GUIDES: Final[tuple[GuideEntry, ...]] = (
    GuideEntry(
        "backup_321",
        "Backup-Strategie (3-2-1)",
        "Doku_BACKUP_321_ALLGEMEIN.pdf",
        ("backup", "sicherung", "datensicherung", "3-2-1", "wiederherstell",
         "restore", "ausfall", "ransom"),
    ),
    GuideEntry(
        "verschluesselung",
        "Daten verschlüsseln & verschlüsselte Backups",
        "Doku_VERSCHLUESSELTE_BACKUPS_ALLGEMEIN.pdf",
        ("verschlüssel", "verschluessel", "encryption", "bitlocker", "krypto",
         "schlüssel", "schluessel", "festplatte"),
    ),
    GuideEntry(
        "lieferkette",
        "Lieferketten & Abhängigkeiten absichern",
        "Doku_DEPENDENCY_MAP_ALLGEMEIN.pdf",
        ("lieferant", "supply", "dependency", "abhängig", "abhaengig",
         "drittanbieter", "avv", "sbom", "vendor"),
    ),
    GuideEntry(
        "ki_securitychat",
        "Sicher mit dem KI-Assistenten arbeiten",
        "Doku_LLM_SECURITYCHAT_ALLGEMEIN.pdf",
        ("ki-chat", "ki-assistent", "llm", "prompt", "ollama", "chatbot"),
    ),
    GuideEntry(
        "ki_zuverlaessigkeit",
        "Zuverlässigkeit von KI-Agenten",
        "Doku_KI_AGENT_ZUVERLAESSIGKEIT_ALLGEMEIN.pdf",
        ("ki-agent", "halluzin", "zuverlässig", "zuverlaessig", "agent"),
    ),
    # Fallback / Basisschutz — bewusst zuletzt, damit thematische Treffer
    # (Backup/Verschluesselung/…) Vorrang haben.
    GuideEntry(
        _FALLBACK_KEY,
        "IT-Grundschutz für KMU",
        "Doku_GRUNDSCHUTZ_KMU_ALLGEMEIN.pdf",
        ("grundschutz", "härtung", "haertung", "hardening", "firewall",
         "update", "patch", "passwort", "basisschutz", "uac", "rdp"),
    ),
)


def guides_root() -> Path:
    """Verzeichnis der gebuendelten Leitfaden-PDFs (dev + frozen).

    Im Build (PyInstaller) ``sys._MEIPASS``, sonst der Repo-Root (eine Ebene
    ueber diesem Modul: core → root).
    """
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / _GUIDES_SUBPATH  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[1] / _GUIDES_SUBPATH


def guide_path(entry: GuideEntry) -> Path:
    """Absoluter Pfad zur PDF-Datei eines Leitfadens."""
    return guides_root() / entry.filename


def guide_exists(entry: GuideEntry) -> bool:
    """True, wenn die PDF-Datei tatsaechlich vorhanden ist (gebuendelt)."""
    try:
        return guide_path(entry).is_file()
    except OSError:
        return False


def alle_guides() -> tuple[GuideEntry, ...]:
    """Alle registrierten Leitfaden-Eintraege (auch nicht gebuendelte)."""
    return _GUIDES


def match_guides(text: str, *, limit: int = 2) -> list[GuideEntry]:
    """Findet bis zu ``limit`` thematisch passende, VORHANDENE Leitfaden.

    Matcht ``text`` (z. B. Todo-Titel + Beschreibung + Quell-Tool, lowercase)
    gegen die ``schlagworte``. Nur gebuendelte Guides (``guide_exists``) werden
    zurueckgegeben — fehlt eine PDF (z. B. Customer-Build ohne Guides), faellt
    die Funktion still auf weniger/keine Treffer zurueck.

    Args:
        text: Frei-Text zum Klassifizieren.
        limit: Maximale Anzahl Treffer.

    Returns:
        Passende Leitfaden in Registry-Reihenfolge (thematisch vor Fallback).
    """
    low = (text or "").lower()
    treffer = [
        g
        for g in _GUIDES
        if any(wort in low for wort in g.schlagworte) and guide_exists(g)
    ]
    return treffer[:limit]


def fallback_guide() -> GuideEntry | None:
    """Der allgemeine Grundschutz-Leitfaden, falls vorhanden (sonst ``None``)."""
    eintrag = next((g for g in _GUIDES if g.key == _FALLBACK_KEY), None)
    return eintrag if (eintrag is not None and guide_exists(eintrag)) else None
