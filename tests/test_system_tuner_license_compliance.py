"""
test_system_tuner_license_compliance — Katalog-Provenienz-Gate (R3, Phase 2b).

Verifiziert die 5. Ebene von ``license_compliance.scan_catalog_provenance``:
der system_tuner-Katalog muss AGPL-frei sein (Build/CI fail-closed).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from license_compliance import scan_catalog_provenance


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_catalog(tmp_path: Path, name: str, license_str: str) -> None:
    catalog_dir = tmp_path / "resources" / "system_tuner"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    (catalog_dir / name).write_text(
        "catalog_version: '1.0'\n"
        "tweaks:\n"
        "  - id: TW-X\n"
        "    provenance:\n"
        "      source: Microsoft Learn\n"
        f"      license: {license_str}\n",
        encoding="utf-8",
    )


def test_real_catalog_is_agpl_free() -> None:
    assert scan_catalog_provenance(_repo_root()) == []


def test_agpl_license_flagged(tmp_path: Path) -> None:
    _write_catalog(tmp_path, "catalog_bad.yaml", "AGPL-3.0")
    violations = scan_catalog_provenance(tmp_path)
    assert len(violations) == 1
    assert "AGPL-3.0" in violations[0]


def test_gpl_and_lgpl_flagged(tmp_path: Path) -> None:
    _write_catalog(tmp_path, "catalog_gpl.yaml", "GPL-3.0")
    assert scan_catalog_provenance(tmp_path)


def test_mit_license_ok(tmp_path: Path) -> None:
    _write_catalog(tmp_path, "catalog_ok.yaml", "MIT")
    assert scan_catalog_provenance(tmp_path) == []


def test_missing_catalog_dir_no_error(tmp_path: Path) -> None:
    assert scan_catalog_provenance(tmp_path) == []
