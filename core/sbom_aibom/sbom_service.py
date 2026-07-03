"""core/sbom_aibom/sbom_service.py — CycloneDX-1.5-SBOM aus den installierten
Python-Dependencies.

Liest die Metadaten aller im aktiven Python-Environment installierten
Distributions via:mod:`importlib.metadata` und mappt sie auf das
CycloneDX-1.5-JSON-Schema. Kein neues Runtime-Dependency notwendig
(``importlib.metadata`` ist Stdlib, ``packaging`` ist bereits gepinnt).

Treiber: EU Cyber Resilience Act (CRA), NIS2-Lieferkette, BSI-Anforderungen
zur Software-Stueckliste.

.
"""

from __future__ import annotations

import json
import platform
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
from pathlib import Path

from core.logger import get_logger
from core.version import __version__ as _NORISK_VERSION

_log = get_logger(__name__)

_CYCLONEDX_SPEC_VERSION = "1.5"
_BOM_FORMAT = "CycloneDX"


@dataclass(frozen=True)
class SbomComponent:
    """Eine SBOM-Komponente (eine installierte Distribution).

    Args:
        name: Distribution-Name laut Metadaten (z. B. ``"PySide6"``).
        version: Distribution-Version (z. B. ``"6.11.0"``).
        purl: Package-URL gemaess purl-spec, z. B.
            ``"pkg:pypi/pyside6@6.11.0"``.
        bom_ref: Eindeutige Referenz innerhalb der SBOM.
        licenses: Liste von Lizenz-IDs/-Texten aus den Distribution-Metadaten.
        author: Optionaler Author-String aus den Metadaten.
        description: Optionale Kurzbeschreibung aus den Metadaten.
    """

    name: str
    version: str
    purl: str
    bom_ref: str
    licenses: list[str] = field(default_factory=list)
    author: str = ""
    description: str = ""


def _normalize_distribution_name(raw_name: str) -> str:
    """Normalisiert einen PyPI-Distributionsnamen gemaess PEP 503.

    PyPI-Namen werden lowercase und mit ``-`` als Trenner geschrieben
    (``Foo_Bar`` und ``foo.bar`` werden beide zu ``foo-bar``). Wichtig
    fuer die ``purl``-Erzeugung (purl-spec verlangt PEP-503-Normalform).

    Args:
        raw_name: Distributionsname wie er in den Metadaten steht.

    Returns:
        Normalisierter Name (lowercase, alle ``_`` und ``.`` zu ``-``).
    """
    return raw_name.lower().replace("_", "-").replace(".", "-")


def _extract_licenses(meta: importlib_metadata.PackageMetadata) -> list[str]:
    """Extrahiert Lizenz-Eintraege aus den Distribution-Metadaten.

    Args:
        meta: ``PackageMetadata``-Objekt einer Distribution.

    Returns:
        Liste der gefundenen Lizenz-Strings (kann leer sein).
    """
    licenses: list[str] = []
    license_field = meta.get("License")
    if license_field and license_field != "UNKNOWN":
        licenses.append(license_field)
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            parts = [p.strip() for p in classifier.split("::")[1:]]
            if parts:
                lic = parts[-1]
                if lic and lic not in licenses:
                    licenses.append(lic)
    return licenses


def _component_from_distribution(
    dist: importlib_metadata.Distribution,
) -> SbomComponent | None:
    """Konvertiert eine einzelne ``Distribution`` zu einer ``SbomComponent``.

    Args:
        dist: Distribution-Objekt aus ``importlib.metadata.distributions``.

    Returns:
        ``SbomComponent`` oder ``None`` wenn die Distribution keinen Namen
        liefert (defekte/teilweise Installation).
    """
    meta = dist.metadata
    raw_name = meta.get("Name") or ""
    if not raw_name:
        return None
    version = dist.version or "0.0.0"
    normalized = _normalize_distribution_name(raw_name)
    purl = f"pkg:pypi/{normalized}@{version}"
    bom_ref = f"{normalized}@{version}"
    return SbomComponent(
        name=raw_name,
        version=version,
        purl=purl,
        bom_ref=bom_ref,
        licenses=_extract_licenses(meta),
        author=meta.get("Author") or "",
        description=meta.get("Summary") or "",
    )


def build_sbom() -> list[SbomComponent]:
    """Sammelt alle installierten Distributions als SBOM-Komponenten.

    Returns:
        Alphabetisch nach Distributionsname sortierte Liste.
    """
    components: list[SbomComponent] = []
    for dist in importlib_metadata.distributions():
        component = _component_from_distribution(dist)
        if component is not None:
            components.append(component)
    components.sort(key=lambda c: c.name.lower())
    return components


def _component_to_cyclonedx(component: SbomComponent) -> dict[str, object]:
    """Mappt eine ``SbomComponent`` auf das CycloneDX-1.5-Komponenten-Objekt.

    Args:
        component: Die SBOM-Komponente.

    Returns:
        Dict im CycloneDX-1.5-Schema (Felder ``type``/``name``/``version``/
        ``purl``/``bom-ref`` sind Pflicht laut Spec).
    """
    payload: dict[str, object] = {
        "type": "library",
        "bom-ref": component.bom_ref,
        "name": component.name,
        "version": component.version,
        "purl": component.purl,
    }
    if component.author:
        payload["author"] = component.author
    if component.description:
        payload["description"] = component.description
    if component.licenses:
        payload["licenses"] = [
            {"license": {"name": lic}} for lic in component.licenses
        ]
    return payload


class SbomService:
    """Erzeugt CycloneDX-1.5-konforme SBOMs aus dem aktuellen Python-Environment.

    Beispiel:
        >>> service = SbomService
        >>> bom = service.generate
        >>> service.export_json(bom, Path("bom.cdx.json"))
    """

    def generate(self) -> dict[str, object]:
        """Erzeugt eine vollstaendige CycloneDX-1.5-SBOM als Dict.

        Returns:
            CycloneDX-1.5-konformes BOM-Dict (serialisierbar via ``json.dumps``).
        """
        components = build_sbom()
        serial = f"urn:uuid:{uuid.uuid4()}"
        bom: dict[str, object] = {
            "bomFormat": _BOM_FORMAT,
            "specVersion": _CYCLONEDX_SPEC_VERSION,
            "serialNumber": serial,
            "version": 1,
            "metadata": self._build_metadata(),
            "components": [_component_to_cyclonedx(c) for c in components],
        }
        _log.info("SBOM generiert: %d Komponenten", len(components))
        return bom

    def export_json(self, bom: dict[str, object], target: Path) -> Path:
        """Schreibt die SBOM als JSON-Datei.

        Args:
            bom: BOM-Dict aus:meth:`generate`.
            target: Zielpfad (Eltern-Verzeichnis wird angelegt).

        Returns:
            Der geschriebene Pfad.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(bom, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        _log.info("SBOM exportiert: %s", target)
        return target

    def _build_metadata(self) -> dict[str, object]:
        """Erzeugt den ``metadata``-Block der CycloneDX-BOM.

        Returns:
            ``timestamp`` (ISO-8601 UTC) + ``tools`` (Generator-Hinweis) +
            ``component`` (die analysierte App selbst).
        """
        return {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "FINLAI designs",
                    "name": "NoRisk SBOM Generator",
                    "version": _NORISK_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"norisk@{_NORISK_VERSION}",
                "name": "NoRisk by FINLAI",
                "version": _NORISK_VERSION,
                "description": (
                    f"Generiert auf Python {platform.python_version()} "
                    f"({sys.implementation.name})."
                ),
            },
        }
