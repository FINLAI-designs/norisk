"""
handbook_source — Lädt das Anwenderhandbuch (.md) für den In-App-HelpDialog.

**Single Source of Truth:** Der Handbuch-Reiter des HelpDialogs rendert dieselbe
Datei ``docs/ANWENDERHANDBUCH_NORISK.md`` wie der PDF-Export und der Chatbot-RAG —
inklusive der eingebetteten Screenshots und der ausführlichen Funktionsbeschreibungen.
Damit entfällt die frühere Doppelpflege (In-App-Text aus ``help_content.py`` vs.
Handbuch-Datei); ``help_content.py`` bleibt weiterhin für die In-Tool-Tooltips zuständig.

Dieses Modul parst das Markdown in navigierbare Abschnitte (Kapitel ``##`` +
Unterkapitel ``###``) und löst den Bild-Basis-Pfad auf. Reine Datei-/Parse-Logik,
kein PySide6 — voll testbar.

Schichtzugehörigkeit: core/ — keine GUI, keine Netzwerk-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.logger import get_logger

_log = get_logger(__name__)

#: App-ID → Handbuch-Dateiname (spiegelt document_loader._HANDBUCH_MAP).
_HANDBUCH_MAP: dict[str, str] = {
    "finlai": "ANWENDERHANDBUCH_FINLAI.md",
    "norisk": "ANWENDERHANDBUCH_NORISK.md",
    "automate": "ANWENDERHANDBUCH_AUTOMATE.md",
}
_DEFAULT_HANDBUCH = "ANWENDERHANDBUCH_NORISK.md"

#: Erkennt Kapitel-/Unterkapitel-Überschriften (## / ###), NICHT #, #### oder tiefer.
_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+?)\s*$")
#: Führendes Abschnitts-Nummernpräfix („7", „7.4", „11.1") als stabile Kennung.
_NUMBER_RE = re.compile(r"^(\d+(?:\.\d+)?)\b")
#: Überschriften, die als Navigations-Eintrag nichts beitragen (redundant zur Nav).
_SKIP_TITLES: frozenset[str] = frozenset({"Inhaltsverzeichnis"})


@dataclass(frozen=True, slots=True)
class HandbookSection:
    """Ein navigierbarer Handbuch-Abschnitt (Kapitel oder Unterkapitel).

    Attributes:
        level: Markdown-Ebene — ``2`` für Kapitel (``##``), ``3`` für
            Unterkapitel (``###``).
        number: Stabile Kennung aus dem Nummernpräfix der Überschrift
            (z. B. ``"7"`` oder ``"7.4"``); leer, wenn die Überschrift keines trägt.
        title: Volle Überschrift ohne die ``#``-Zeichen.
        body: Markdown des Abschnitts (Überschrift + Inhalt bis zur nächsten
            Überschrift gleicher oder höherer Ebene — überschneidungsfrei).
    """

    level: int
    number: str
    title: str
    body: str


def _docs_dir() -> Path:
    """Verzeichnis mit den Handbuch-Dateien (``<repo>/docs``, wie ``DocumentLoader``)."""
    return Path(__file__).resolve().parents[2] / "docs"


def handbook_path(app_name: str = "norisk") -> Path:
    """Absoluter Pfad zur Anwenderhandbuch-Datei der App."""
    filename = _HANDBUCH_MAP.get(app_name, _DEFAULT_HANDBUCH)
    return _docs_dir() / filename


def images_base_uri(app_name: str = "norisk") -> str:
    """``file://``-URI des Handbuch-Verzeichnisses (Basis für ``images/…``-Bilder).

    Der Aufrufer ersetzt relative Bild-Links ``](images/…`` durch
    ``](<uri>/images/…``, damit der QTextBrowser die Screenshots lädt.
    """
    return handbook_path(app_name).parent.as_uri()


def load_sections(app_name: str = "norisk") -> list[HandbookSection]:
    """Parst das Anwenderhandbuch in überschneidungsfreie Abschnitte.

    Jeder ``##``-/``###``-Abschnitt läuft von seiner Überschrift bis zur nächsten
    Überschrift (beliebiger Ebene) — ein Kapitel liefert also seinen Intro-Text, die
    Unterkapitel je ihren eigenen Text. Die Inhaltsverzeichnis-Überschrift wird
    übersprungen (redundant zur Navigation).

    Args:
        app_name: App-ID zur Auswahl der Handbuch-Datei.

    Returns:
        Abschnitte in Dokument-Reihenfolge; leere Liste, wenn die Datei fehlt oder
        nicht lesbar ist (der HelpDialog fällt dann auf einen Hinweis zurück).
    """
    path = handbook_path(app_name)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        _log.warning("Handbuch nicht lesbar (%s): %s", path.name, type(exc).__name__)
        return []

    lines = text.split("\n")
    heads: list[tuple[int, int, str]] = []  # (zeilen-index, level, titel)
    for idx, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if match:
            heads.append((idx, len(match.group(1)), match.group(2).strip()))

    sections: list[HandbookSection] = []
    for pos, (idx, level, title) in enumerate(heads):
        if title in _SKIP_TITLES:
            continue
        end = heads[pos + 1][0] if pos + 1 < len(heads) else len(lines)
        body = "\n".join(lines[idx:end]).strip()
        num_match = _NUMBER_RE.match(title)
        number = num_match.group(1) if num_match else ""
        sections.append(HandbookSection(level, number, title, body))
    return sections
