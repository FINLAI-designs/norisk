"""
json_parser — Parst JSON-Dateien mit Package-Listen fuer den Dependency-Auditor.

Unterstuetzte Formate:
  1. Array von Objekten: ``[{"name": "requests", "version": "2.31.0"},...]``
     Akzeptiert auch ``"package"`` statt ``"name"`` als Schluessel.
  2. Objekt mit ``"dependencies"``-Schluessel (package.json-Stil):
     ``{"dependencies": {"requests": "2.31.0", "flask": ">=2.0"}}``
  3. Array von Strings im requirements-Format:
     ``["requests==2.31.0", "flask>=2.0"]``

Sicherheit:
  - Dateipfad wird ueber validate_file_path geprueft (Path-Traversal-Schutz)
  - Nur.json Dateien erlaubt
  - Max 10 000 Eintraege — Schutz vor ueberlangen Dateien

Schichtzugehoerigkeit: data/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json

from core.exceptions import ValidationError
from core.security.validators import validate_file_path
from tools.dependency_auditor.data.requirements_parser import (
    _normalize_name,
    _parse_line,
)
from tools.dependency_auditor.domain.models import DependencyInfo

_MAX_ENTRIES = 10_000


def parse_json_dependencies(file_path: str) -> list[DependencyInfo]:
    """Parst eine JSON-Datei mit Package-Informationen.

    Args:
        file_path: Pfad zur JSON-Datei (wird validiert).

    Returns:
        Liste der geparsten DependencyInfo-Objekte.

    Raises:
        ValueError: Wenn der Pfad ungueltig, das Format unbekannt oder
                    die Datei kein gueltiges JSON enthaelt.
        FileNotFoundError: Wenn die Datei nicht existiert.
    """
    validated = validate_file_path(file_path, ["json"])

    with open(validated, encoding="utf-8", errors="replace") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Ungültiges JSON: {exc}") from exc

    return _dispatch(raw)


def _dispatch(raw: object) -> list[DependencyInfo]:
    """Erkennt das Format und delegiert ans passende Parsing.

    Args:
        raw: Geparste JSON-Struktur.

    Returns:
        Liste der DependencyInfo-Objekte.

    Raises:
        ValueError: Bei unbekanntem Format.
    """
    if isinstance(raw, list):
        if not raw:
            return []
        # Format 3: Liste von Strings ("requests==2.31.0")
        if isinstance(raw[0], str):
            return _parse_string_list(raw)
        # Format 1: Liste von Objekten
        if isinstance(raw[0], dict):
            return _parse_object_list(raw)
        raise ValidationError("JSON-Array enthält weder Strings noch Objekte.")

    if isinstance(raw, dict):
        # Format 2: {"dependencies": {"pkg": "version"}}
        deps = raw.get("dependencies") or raw.get("packages") or raw.get("requires")
        if isinstance(deps, dict):
            return _parse_dict_deps(deps)
        # Direktes Objekt-Dict: {"requests": "2.31.0"}
        # Erkennungsmerkmal: alle Werte sind Strings
        if all(isinstance(v, str) for v in raw.values()):
            return _parse_dict_deps(raw)
        raise ValidationError(
            "JSON-Objekt: kein 'dependencies'-Schlüssel und kein Package-Dict erkannt."
        )

    raise ValidationError(f"Unbekanntes JSON-Format: {type(raw).__name__}")


def _parse_object_list(entries: list) -> list[DependencyInfo]:
    """Parst eine Liste von Objekten ``{"name":..., "version":...}``.

    Args:
        entries: Liste der Objekte aus dem JSON-Array.

    Returns:
        Liste der DependencyInfo-Objekte.
    """
    result: list[DependencyInfo] = []
    for line_no, entry in enumerate(entries[:_MAX_ENTRIES], start=1):
        if not isinstance(entry, dict):
            continue
        name_raw = entry.get("name") or entry.get("package") or entry.get("pkg") or ""
        version = entry.get("version") or entry.get("ver") or ""
        if not name_raw:
            continue
        name = _normalize_name(str(name_raw))
        version_pinned = str(version) if version else None
        version_spec = f"=={version_pinned}" if version_pinned else ""
        result.append(
            DependencyInfo(
                name=name,
                version_pinned=version_pinned,
                version_spec=version_spec,
                line_number=line_no,
            )
        )
    return result


def _parse_string_list(entries: list) -> list[DependencyInfo]:
    """Parst eine Liste von Strings im requirements-Format.

    Args:
        entries: Liste der Strings.

    Returns:
        Liste der DependencyInfo-Objekte.
    """
    result: list[DependencyInfo] = []
    for line_no, entry in enumerate(entries[:_MAX_ENTRIES], start=1):
        dep = _parse_line(str(entry), line_no)
        if dep is not None:
            result.append(dep)
    return result


def _parse_dict_deps(deps: dict) -> list[DependencyInfo]:
    """Parst ein Package-Dict ``{"name": "version_spec"}``.

    Args:
        deps: Mapping Package-Name → Versions-Spezifikation.

    Returns:
        Liste der DependencyInfo-Objekte.
    """
    result: list[DependencyInfo] = []
    for line_no, (raw_name, raw_version) in enumerate(
        list(deps.items())[:_MAX_ENTRIES], start=1
    ):
        name = _normalize_name(str(raw_name))
        version_spec = str(raw_version).strip() if raw_version else ""
        # Gepinnte Version extrahieren
        import re  # noqa: PLC0415

        pin_m = re.search(r"==\s*([^\s,;]+)", version_spec)
        version_pinned = pin_m.group(1) if pin_m else None
        result.append(
            DependencyInfo(
                name=name,
                version_pinned=version_pinned,
                version_spec=version_spec,
                line_number=line_no,
            )
        )
    return result
