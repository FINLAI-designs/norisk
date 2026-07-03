"""tests/test_key_manager_context — Set/Get-API des KeyManager-Modul-State.

Testet:mod:`core.database.key_manager_context` — den Modul-State-
Container, der die Variante-A-Verkabelung des KeyManager an die
Konsumenten realisiert (siehe §2.5 Architektur-Entscheidung
2026-05-04, Subtask 2).

Test-Isolation: Jeder Test bekommt via ``_reset_module_state``-
Autouse-Fixture einen sauberen Modul-State. Damit kann kein Test
einen aktiven KeyManager an einen anderen Test leaken — Test-
Pollution durch globalen State ist die einzige echte Schwaeche der
Variante A, und diese Fixture ist die Gegenmassnahme.

Stub-Strategie: Tests nutzen einen ``KeyManager(InMemoryDPAPIBackend)``
ohne ``initialize``-Aufruf. Das Context-Modul haelt nur die
Referenz; es ruft keine KeyManager-API. Damit reicht ein leerer
Stub-KeyManager — kein DPAPI, kein Disk-Zugriff, kein DEK.

Author: Patrick Riederich
Version: 1.0 (Subtask 2 Variante A §2.5)
"""

from __future__ import annotations

import pytest

from core.database.key_manager import KeyManager
from core.database.key_manager_context import (
    get_active_key_manager,
    set_active_key_manager,
)
from core.database.key_manager_platform import InMemoryDPAPIBackend

# Subtask 2: Diese Tests verifizieren das Set/Get-Verhalten
# des Modul-State direkt — der globale conftest-Bootstrap (
# tests/conftest.py) wuerde den Modul-State pre-populieren und damit
# z. B. test_module_state_isolated_per_test_baseline brechen.
pytestmark = pytest.mark.no_key_manager_bootstrap


@pytest.fixture(autouse=True)
def _reset_module_state():
    """Stellt sicher, dass jeder Test mit leerem Modul-State startet
    und ihn beim Ende wieder leert.

    Pflicht-Fixture — ohne sie wuerde ein Test-Ausreisser den
    Modul-State an Folgetests vererben (Test-Pollution).
    """
    set_active_key_manager(None)
    yield
    set_active_key_manager(None)


@pytest.fixture
def stub_km() -> KeyManager:
    """Liefert einen leichtgewichtigen Stub-KeyManager.

    Verwendet ``InMemoryDPAPIBackend``, ruft KEIN ``initialize``.
    Reicht fuer Set/Get-Tests, weil das Context-Modul nur eine
    Referenz haelt und keine Methode des KeyManager aufruft.
    """
    return KeyManager(backend=InMemoryDPAPIBackend())


class TestKeyManagerContext:
    """Set/Get-Roundtrip + Edge-Cases der Modul-State-API."""

    def test_set_and_get_returns_same_instance(self, stub_km: KeyManager) -> None:
        """Nach ``set_active_key_manager(km)`` liefert ``get_active_key_manager``
        genau dieselbe Instanz zurueck (Identitaet, nicht nur Gleichheit)."""
        set_active_key_manager(stub_km)
        assert get_active_key_manager() is stub_km

    def test_get_without_set_raises_runtime_error(self) -> None:
        """Ohne vorheriges ``set_active_key_manager(km)`` wirft
        ``get_active_key_manager`` einen ``RuntimeError`` mit
        Hinweis auf den Bootstrap-Pfad."""
        with pytest.raises(RuntimeError, match="Kein aktiver KeyManager"):
            get_active_key_manager()

    def test_set_to_none_disables_lookup_then_get_raises(
        self, stub_km: KeyManager
    ) -> None:
        """Explizites ``set_active_key_manager(None)`` deaktiviert
        den Lookup — der naechste ``get_active_key_manager``-Aufruf
        wirft erneut ``RuntimeError``. Wichtig fuer Shutdown-Pfad in
        ``launch_app`` und fuer Test-Teardown."""
        set_active_key_manager(stub_km)
        set_active_key_manager(None)
        with pytest.raises(RuntimeError):
            get_active_key_manager()

    def test_set_after_none_works_again(self, stub_km: KeyManager) -> None:
        """Nach ``set_active_key_manager(None)`` darf ein erneutes
        ``set_active_key_manager(km)`` den Manager wieder
        aktivieren — Re-Initialisierung ist erlaubt."""
        set_active_key_manager(stub_km)
        set_active_key_manager(None)
        set_active_key_manager(stub_km)
        assert get_active_key_manager() is stub_km

    def test_module_state_isolated_per_test_baseline(self) -> None:
        """Schutztest: nach Autouse-Fixture-Reset darf kein Manager
        mehr aktiv sein — verifiziert die Test-Isolation gegenueber
        anderen Tests in dieser Datei."""
        with pytest.raises(RuntimeError):
            get_active_key_manager()
