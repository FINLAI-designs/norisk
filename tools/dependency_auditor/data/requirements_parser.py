"""
requirements_parser — Parst requirements.txt-Dateien.

Unterstuetzt:
  - Exakt gepinnte Versionen: ``requests==2.32.5``
  - Minimum/Range-Specs: ``requests>=2.30``, ``requests>=2.30,<3``
  - Extras: ``requests[security]==2.32.5`` → name="requests"
  - Kommentare (``#``) und Leerzeilen → uebersprungen
  - ``-r includes`` → uebersprungen (kein rekursives Parsen)
  - Environment-Marker (``; python_version>="3.10"``) → abgeschnitten

Sicherheit:
  - Dateipfad wird ueber validate_file_path geprueft (Path-Traversal-Schutz)
  - Nur.txt und.pip Dateien erlaubt

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re

from core.security.validators import validate_file_path
from tools.dependency_auditor.domain.models import DependencyInfo

# ---------------------------------------------------------------------------
# Muster fuer Package-Zeilen
# ---------------------------------------------------------------------------

# Erfasst Extras und Name: ``requests[security]`` oder ``requests``
_RE_PKG_NAME = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?"
)

# Pinned == Operator
_RE_PINNED = re.compile(r"==\s*([^\s,;]+)")


def parse_requirements(file_path: str) -> list[DependencyInfo]:
    """Parst eine requirements.txt-Datei in DependencyInfo-Objekte.

    Zeilen die beginnen mit ``#``, ``-r``, ``-c``, ``-e``, ``http``
    oder leer sind, werden uebersprungen.

    Args:
        file_path: Pfad zur requirements.txt (wird validiert).

    Returns:
        Liste der geparsten DependencyInfo-Objekte.

    Raises:
        ValueError: Wenn der Pfad ungueltig ist oder die Endung nicht
                    ``.txt`` / ``.pip`` ist.
        FileNotFoundError: Wenn die Datei nicht existiert.
    """
    validated = validate_file_path(file_path, ["txt", "pip"])

    result: list[DependencyInfo] = []

    with open(validated, encoding="utf-8", errors="replace") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            dep = _parse_line(raw_line, line_no)
            if dep is not None:
                result.append(dep)

    return result


def _parse_line(raw_line: str, line_number: int) -> DependencyInfo | None:
    """Parst eine einzelne Zeile aus requirements.txt.

    Args:
        raw_line: Rohe Zeile inklusive Zeilenumbruch.
        line_number: Zeilennummer (1-basiert).

    Returns:
        DependencyInfo oder None wenn die Zeile uebersprungen werden soll.
    """
    # Inline-Kommentar und Environment-Marker entfernen
    line = raw_line.strip()

    # Leerzeilen und Kommentarzeilen
    if not line or line.startswith("#"):
        return None

    # Direktiven (Options-Flags)
    if line.startswith(("-r", "-c", "-e", "-f", "--", "http://", "https://")):
        return None

    # Inline-Kommentar abschneiden (spaeter im String)
    if " #" in line:
        line = line[: line.index(" #")].strip()

    # Environment-Marker abschneiden (z. B. ``; python_version >= "3.10"``)
    if ";" in line:
        line = line[: line.index(";")].strip()

    if not line:
        return None

    # Package-Name extrahieren
    m = _RE_PKG_NAME.match(line)
    if not m:
        return None

    raw_name = m.group(1)
    name = _normalize_name(raw_name)

    # Versions-Spezifikation: alles nach dem Namen (incl. Extras-Bracket)
    name_end = m.end()
    version_spec = line[name_end:].strip()

    # Gepinnte Version extrahieren (== operator)
    version_pinned: str | None = None
    pin_m = _RE_PINNED.search(version_spec)
    if pin_m:
        version_pinned = pin_m.group(1)

    return DependencyInfo(
        name=name,
        version_pinned=version_pinned,
        version_spec=version_spec,
        line_number=line_number,
    )


def _normalize_name(name: str) -> str:
    """Normalisiert einen Package-Namen (PEP 503: lowercase, Bindestriche).

    Args:
        name: Roher Package-Name.

    Returns:
        Normalisierter Name.
    """
    return re.sub(r"[-_.]+", "-", name).lower()
