"""
tests/conftest.py — Gemeinsame pytest-Fixtures fuer alle Tests.

Wird von pytest automatisch geladen. Die hier definierten Fixtures
stehen in allen Testdateien ohne expliziten Import zur Verfuegung.

Cleanup 2026-04-28: Der ki_agenten-Cleanup-Hook wurde entfernt -- das
Tool existiert in NoRisk nicht.

Subtask 2: Globaler KeyManager-Bootstrap fuer
alle Tests. EncryptedDatabase und SecureStorage benoetigen seit
Subtask 2 einen aktiven KeyManager im Modul-State. Die globale
Autouse-Fixture stellt einen test-isolierten KeyManager mit
``InMemoryDPAPIBackend`` bereit, monkeypatcht ``_MASTER_KEY_FILE``
auf ein Session-tmp-Verzeichnis und aktiviert ihn vor jedem Test.

Tests, die KeyManager-Verhalten direkt testen
(``test_key_manager.py``, ``test_key_manager_context.py``), setzen
am Top des Files ``pytestmark = pytest.mark.no_key_manager_bootstrap``,
um die globale Fixture zu deaktivieren — sie verwalten den
Modul-State explizit.
"""

import pytest


def pytest_configure(config):
    """Registriert benutzerdefinierte Marker."""
    config.addinivalue_line(
        "markers",
        "no_key_manager_bootstrap: deaktiviert den globalen KeyManager-"
        "Bootstrap (siehe tests/conftest.py). Tests, die KeyManager-Verhalten "
        "direkt testen, setzen pytestmark auf diesen Marker, um den "
        "Modul-State selbst zu verwalten.",
    )


@pytest.fixture(autouse=True)
def _clear_last_scan_cache():
    """Perf C-Hebel-2: der Last-Scan-Cache (last_scan_registry) ist modul-global
    -> vor und nach JEDEM Test leeren, damit ein gecachter Wert nicht in den
    naechsten Test leakt (Test-Hygiene)."""
    from core.registry.last_scan_registry import clear_cache

    clear_cache()
    yield
    clear_cache()


@pytest.fixture(autouse=True)
def _clear_db_app_id():
    """: der DB-Konsolidierungs-Remap (EncryptedDatabase) haengt am
    modul-globalen App-Kontext. Vor UND nach jedem Test zuruecksetzen, damit
    ein in einem Test gesetztes ``app_id`` nicht leakt und nachfolgende Tests
    nicht unerwartet auf ``norisk`` konsolidiert (Test-Isolation). Tests, die
    den Kontext brauchen, setzen ihn weiterhin selbst im Body."""
    from core.database.db_context import clear_db_app_id

    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture(autouse=True)
def _ensure_global_key_manager(request, tmp_path_factory, monkeypatch):
    """Globaler KeyManager-Bootstrap fuer alle Tests (Subtask 2).

    Stellt einen test-isolierten KeyManager mit ``InMemoryDPAPIBackend``
    bereit und aktiviert ihn via Modul-State. Damit funktionieren alle
    Tests, die ``EncryptedDatabase`` oder ``SecureStorage`` transitiv
    nutzen, ohne eigenes Bootstrap-Setup.

    Der ``_MASTER_KEY_FILE``-Pfad wird auf ein Session-tmp-Verzeichnis
    gepatcht (``tmp_path_factory.mktemp``) — die Production-Datei
    ``~/.finlai/master.key.wrapped`` wird NIE von Tests beruehrt.

    Tests mit ``@pytest.mark.no_key_manager_bootstrap`` deaktivieren
    die Fixture und verwalten den KeyManager-Modul-State selbst
    (siehe ``tests/test_key_manager.py``,
    ``tests/test_key_manager_context.py``).
    """
    if request.node.get_closest_marker("no_key_manager_bootstrap"):
        yield
        return

    from core.database import encrypted_db as enc_db_mod
    from core.database import key_manager as km_module
    from core.database.key_manager import KeyManager
    from core.database.key_manager_context import set_active_key_manager
    from core.database.key_manager_platform import InMemoryDPAPIBackend

    tmp_dir = tmp_path_factory.mktemp("envelope_km")
    monkeypatch.setattr(
        km_module,
        "_MASTER_KEY_FILE",
        tmp_dir / "master.key.wrapped",
    )
    # DB_DIR-Patch: verhindert dass Tests Production-DBs in
    # ~/.finlai/db/ anfassen. Latenter Test-Hygiene-Bug, durch
    # Subtask 2 (deterministischer Schluessel-Wechsel) erst sichtbar
    # geworden — strukturell aufgeloest in dieser Fixture.
    monkeypatch.setattr(enc_db_mod, "DB_DIR", tmp_dir / "db")
    km = KeyManager(backend=InMemoryDPAPIBackend())
    km.initialize()
    set_active_key_manager(km)
    yield
    set_active_key_manager(None)
    km.wipe()
