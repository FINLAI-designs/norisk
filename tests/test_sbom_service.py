"""Tests fuer core/sbom_aibom/sbom_service.py.

Prueft die CycloneDX-1.5-Konformitaet (Pflichtfelder pro Komponente), die
Normalisierung der purl-Namen sowie den JSON-Export. Die Tests laufen
plattform-unabhaengig (kein win32-spezifisches Verhalten).

.
"""

from __future__ import annotations

import json

import pytest

from core.sbom_aibom.sbom_service import (
    SbomComponent,
    SbomService,
    _component_to_cyclonedx,
    _normalize_distribution_name,
    build_sbom,
)


def test_normalize_distribution_name_pep503():
    """PEP-503-Normalform: lowercase, ``.`` und ``_`` zu ``-``."""
    assert _normalize_distribution_name("PySide6") == "pyside6"
    assert _normalize_distribution_name("python_docx") == "python-docx"
    assert _normalize_distribution_name("ruamel.yaml") == "ruamel-yaml"
    assert _normalize_distribution_name("Foo_Bar.Baz") == "foo-bar-baz"


def test_build_sbom_returns_nonempty_in_test_env():
    """Im Test-venv sind mindestens ein paar Distributions installiert."""
    components = build_sbom()
    assert len(components) > 0
    for component in components:
        assert component.name
        assert component.version
        assert component.purl.startswith("pkg:pypi/")
        assert component.bom_ref


def test_build_sbom_purl_uses_normalized_name():
    """Die purl muss den PEP-503-normalisierten Distributionsnamen tragen."""
    components = build_sbom()
    pytest_components = [c for c in components if c.name.lower() == "pytest"]
    if not pytest_components:
        pytest.skip("pytest nicht als Distribution gefunden")
    component = pytest_components[0]
    assert component.purl.startswith("pkg:pypi/pytest@")
    assert component.purl.endswith(f"@{component.version}")


def test_component_to_cyclonedx_has_required_fields():
    """CycloneDX-1.5-Komponenten brauchen type/bom-ref/name/version/purl."""
    component = SbomComponent(
        name="example",
        version="1.2.3",
        purl="pkg:pypi/example@1.2.3",
        bom_ref="example@1.2.3",
        licenses=["MIT"],
        author="Beispiel-Author",
        description="Beispielhafte Bibliothek.",
    )
    payload = _component_to_cyclonedx(component)
    assert payload["type"] == "library"
    assert payload["bom-ref"] == "example@1.2.3"
    assert payload["name"] == "example"
    assert payload["version"] == "1.2.3"
    assert payload["purl"] == "pkg:pypi/example@1.2.3"
    assert payload["author"] == "Beispiel-Author"
    assert payload["description"] == "Beispielhafte Bibliothek."
    licenses = payload["licenses"]
    assert isinstance(licenses, list)
    assert licenses == [{"license": {"name": "MIT"}}]


def test_component_to_cyclonedx_omits_empty_optional_fields():
    """Felder author/description/licenses fehlen, wenn sie leer sind."""
    component = SbomComponent(
        name="bare",
        version="0.0.1",
        purl="pkg:pypi/bare@0.0.1",
        bom_ref="bare@0.0.1",
    )
    payload = _component_to_cyclonedx(component)
    assert "author" not in payload
    assert "description" not in payload
    assert "licenses" not in payload


def test_sbom_service_generate_top_level_fields():
    """Der ``generate``-Output hat die CycloneDX-1.5-Top-Level-Pflichtfelder."""
    bom = SbomService().generate()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["version"] == 1
    serial = bom["serialNumber"]
    assert isinstance(serial, str)
    assert serial.startswith("urn:uuid:")
    metadata = bom["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["timestamp"].endswith("Z")
    assert metadata["component"]["type"] == "application"
    assert metadata["component"]["name"] == "NoRisk by FINLAI"
    tools = metadata["tools"]
    assert isinstance(tools, list)
    assert tools[0]["vendor"] == "FINLAI designs"
    components = bom["components"]
    assert isinstance(components, list)
    assert len(components) > 0


def test_sbom_service_export_json_roundtrip(tmp_path):
    """Der Export erzeugt eine lesbare JSON-Datei mit dem generierten Inhalt."""
    service = SbomService()
    bom = service.generate()
    target = tmp_path / "subdir" / "bom.cdx.json"
    written = service.export_json(bom, target)
    assert written == target
    assert target.exists()
    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.5"
    assert parsed["components"] == bom["components"]
