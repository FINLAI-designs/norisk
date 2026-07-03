"""
test_manual_scanner_entries — Tests für manuelle Sicherheitskomponenten-
Einträge (Entity + Repository CRUD).

Nutzt eine temporäre SQLCipher-Datenbank pro Test (monkeypatch auf
``_get_db_dir_for_name``), damit die Tests komplett isoliert und ohne
Berührung der Produktions-DB laufen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tools.system_scanner.domain.entities import ManualScannerEntry
from tools.system_scanner.domain.enums import ComponentStatus, ComponentType

# ---------------------------------------------------------------------------
# Fixture: temporäre SQLCipher-DB pro Test
# ---------------------------------------------------------------------------


@pytest.fixture
def manual_repo(tmp_path, monkeypatch):
    """Liefert ein ``ManualScannerEntryRepository`` mit tmp-DB.

    Patched ``_get_db_dir_for_name`` so dass die ``system_scanner``-DB
    in ``tmp_path`` landet — kein Side-Effect auf das Dev-System.
    """
    import core.database.encrypted_db as edb

    monkeypatch.setattr(edb, "_get_db_dir_for_name", lambda name: tmp_path)
    from tools.system_scanner.data.manual_entry_repository import (
        ManualScannerEntryRepository,
    )

    return ManualScannerEntryRepository()


# ---------------------------------------------------------------------------
# Entity-Tests
# ---------------------------------------------------------------------------


class TestManualScannerEntryEntity:
    """Tests für die Dataclass und ihre Konvertierung."""

    def test_defaults(self) -> None:
        """Ohne Argumente: Status UNKNOWN, leere Version, gesetzte Timestamps."""
        entry = ManualScannerEntry(
            entry_id=None,
            category=ComponentType.ANTIVIRUS,
            name="Test AV",
        )
        assert entry.entry_id is None
        assert entry.category == ComponentType.ANTIVIRUS
        assert entry.name == "Test AV"
        assert entry.version == ""
        assert entry.status == ComponentStatus.UNKNOWN
        assert isinstance(entry.created_at, datetime)
        assert isinstance(entry.updated_at, datetime)

    def test_string_inputs_are_coerced_to_enums(self) -> None:
        """Plain-string Kategorien/Status (z.B. aus QComboBox.currentData) werden
        zu Enum-Instanzen normalisiert — verhindert ``'str' has no attribute 'value'``.
        """
        entry = ManualScannerEntry(
            entry_id=None,
            category="firewall",  # type: ignore[arg-type] — absichtlich str
            name="Test",
            status="active",  # type: ignore[arg-type]
        )
        assert isinstance(entry.category, ComponentType)
        assert entry.category == ComponentType.FIREWALL
        assert isinstance(entry.status, ComponentStatus)
        assert entry.status == ComponentStatus.ACTIVE
        #.value-Aufruf darf jetzt nicht mehr scheitern
        assert entry.category.value == "firewall"
        assert entry.status.value == "active"

    def test_to_security_component_maps_fields(self) -> None:
        """Konvertierung übernimmt Kategorie, Status, Version — Detail bleibt leer."""
        entry = ManualScannerEntry(
            entry_id=5,
            category=ComponentType.FIREWALL,
            name="Windows Defender Firewall",
            version="10.0",
            status=ComponentStatus.ACTIVE,
            created_at=datetime(2026, 4, 24, tzinfo=UTC),
            updated_at=datetime(2026, 4, 24, tzinfo=UTC),
        )
        comp = entry.to_security_component()
        assert comp.name == "Windows Defender Firewall"
        assert comp.type == ComponentType.FIREWALL
        assert comp.status == ComponentStatus.ACTIVE
        assert comp.version == "10.0"
        # Detail bleibt leer — "(manuell)"-Markierung übernimmt die UI.
        assert comp.detail == ""
        # last_updated als ISO-String
        assert "2026-04-24" in comp.last_updated


# ---------------------------------------------------------------------------
# Repository CRUD-Tests
# ---------------------------------------------------------------------------


class TestManualScannerEntryRepository:
    """CRUD-Tests mit echter (tmp) SQLCipher-DB."""

    def test_get_all_empty_initially(self, manual_repo) -> None:
        """Frisches Repo liefert leere Listen pro Kategorie."""
        assert manual_repo.get_all(ComponentType.ANTIVIRUS) == []
        assert manual_repo.get_all(ComponentType.FIREWALL) == []
        assert manual_repo.get_all(ComponentType.ENCRYPTION) == []

    def test_add_sets_entry_id_and_timestamps(self, manual_repo) -> None:
        """``add`` gibt die gespeicherte Entity zurück mit gesetzter ID."""
        entry = ManualScannerEntry(
            entry_id=None,
            category=ComponentType.ANTIVIRUS,
            name="Bitdefender",
            version="7.8.3",
            status=ComponentStatus.ACTIVE,
        )
        saved = manual_repo.add(entry)
        assert saved.entry_id is not None
        assert saved.entry_id > 0
        assert saved.name == "Bitdefender"
        assert saved.status == ComponentStatus.ACTIVE

    def test_get_all_returns_saved_entries(self, manual_repo) -> None:
        """Hinzugefügte Einträge erscheinen in ``get_all`` derselben Kategorie."""
        e1 = manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.ANTIVIRUS,
                name="Bitdefender",
                status=ComponentStatus.ACTIVE,
            )
        )
        e2 = manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.ANTIVIRUS,
                name="Avira",
                status=ComponentStatus.INACTIVE,
            )
        )
        manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.FIREWALL,
                name="Windows Firewall",
                status=ComponentStatus.ACTIVE,
            )
        )
        av_entries = manual_repo.get_all(ComponentType.ANTIVIRUS)
        fw_entries = manual_repo.get_all(ComponentType.FIREWALL)
        assert {e.name for e in av_entries} == {"Bitdefender", "Avira"}
        assert {e.entry_id for e in av_entries} == {e1.entry_id, e2.entry_id}
        assert len(fw_entries) == 1

    def test_category_filter_does_not_leak(self, manual_repo) -> None:
        """Einträge aus anderer Kategorie erscheinen nicht im Filter."""
        manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.ENCRYPTION,
                name="BitLocker",
                status=ComponentStatus.ACTIVE,
            )
        )
        assert manual_repo.get_all(ComponentType.ANTIVIRUS) == []
        assert len(manual_repo.get_all(ComponentType.ENCRYPTION)) == 1

    def test_update_changes_fields(self, manual_repo) -> None:
        """``update`` überschreibt Felder und aktualisiert ``updated_at``."""
        saved = manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.ANTIVIRUS,
                name="Alte Version",
                status=ComponentStatus.INACTIVE,
            )
        )
        saved.name = "Neue Version"
        saved.status = ComponentStatus.ACTIVE
        saved.version = "2.0"
        manual_repo.update(saved)

        reloaded = manual_repo.get_all(ComponentType.ANTIVIRUS)[0]
        assert reloaded.name == "Neue Version"
        assert reloaded.status == ComponentStatus.ACTIVE
        assert reloaded.version == "2.0"

    def test_update_without_id_raises(self, manual_repo) -> None:
        """``update`` auf neuer Entity (entry_id=None) wirft ValueError."""
        entry = ManualScannerEntry(
            entry_id=None,
            category=ComponentType.ANTIVIRUS,
            name="Ghost",
        )
        with pytest.raises(ValueError, match="entry_id"):
            manual_repo.update(entry)

    def test_delete_removes_entry(self, manual_repo) -> None:
        """``delete`` entfernt den Eintrag und gibt True zurück."""
        saved = manual_repo.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.FIREWALL,
                name="Tempfire",
                status=ComponentStatus.ACTIVE,
            )
        )
        assert manual_repo.delete(saved.entry_id) is True
        assert manual_repo.get_all(ComponentType.FIREWALL) == []

    def test_delete_missing_returns_false(self, manual_repo) -> None:
        """``delete`` auf unbekannter ID gibt False zurück, wirft nicht."""
        assert manual_repo.delete(99999) is False

    def test_add_rejects_empty_name(self, manual_repo) -> None:
        """Leere Namen werden abgelehnt."""
        with pytest.raises(ValueError, match="Pflichtfeld"):
            manual_repo.add(
                ManualScannerEntry(
                    entry_id=None,
                    category=ComponentType.ANTIVIRUS,
                    name="   ",
                )
            )

    def test_add_rejects_too_long_name(self, manual_repo) -> None:
        """Namen > 100 Zeichen werden abgelehnt."""
        with pytest.raises(ValueError, match="max\\. 100 Zeichen"):
            manual_repo.add(
                ManualScannerEntry(
                    entry_id=None,
                    category=ComponentType.ANTIVIRUS,
                    name="A" * 101,
                )
            )

    def test_persists_across_new_instance(self, tmp_path, monkeypatch) -> None:
        """Einträge überleben ein neues Repository-Objekt (gleiche DB)."""
        import core.database.encrypted_db as edb

        monkeypatch.setattr(edb, "_get_db_dir_for_name", lambda name: tmp_path)
        from tools.system_scanner.data.manual_entry_repository import (
            ManualScannerEntryRepository,
        )

        repo1 = ManualScannerEntryRepository()
        repo1.add(
            ManualScannerEntry(
                entry_id=None,
                category=ComponentType.ENCRYPTION,
                name="BitLocker",
                status=ComponentStatus.ACTIVE,
            )
        )
        repo2 = ManualScannerEntryRepository()
        entries = repo2.get_all(ComponentType.ENCRYPTION)
        assert len(entries) == 1
        assert entries[0].name == "BitLocker"
