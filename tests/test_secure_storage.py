"""
test_secure_storage — Unit-Tests fuer core/security/encryption.py.

Prueft SecureStorage auf korrekte Verschluesselung, Roundtrip-
Integritaet, Loesch-Funktion und Fehlerverhalten bei beschaedigten
Daten.

Test-Bootstrap: KeyManager-Bootstrap kommt aus dem globalen
``tests/conftest.py``-Autouse-Fixture (Subtask 2).
SecureStorage haengt seitdem am DEK statt am Hardware-Fingerprint.

Author: Patrick Riederich
"""

import json

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_storage(tmp_path, monkeypatch):
    """Gibt eine SecureStorage-Instanz mit isolierten tmp-Pfaden zurueck.

    Subtask 2: KeyManager-Bootstrap erfolgt global via
    ``tests/conftest.py::_ensure_global_key_manager``. Diese Fixture
    isoliert nur die SecureStorage-spezifischen File-Pfade
    (``_STORE_FILE`` fuer verschluesselte Werte, ``_SALT_FILE`` fuer
    den Pre-Subtask-2-Legacy-Pfad — die Migration-only-Replikation
    lebt seit privat in
    ``core.database.migrate_to_envelope._derive_legacy_integrity_key``).
    """
    import core.security.encryption as enc_mod

    salt_file = tmp_path / ".salt"
    store_file = tmp_path / "secure_store.enc"
    monkeypatch.setattr(enc_mod, "_SALT_FILE", salt_file)
    monkeypatch.setattr(enc_mod, "_STORE_FILE", store_file)

    storage = enc_mod.SecureStorage()
    yield storage, store_file, salt_file


# ---------------------------------------------------------------------------
# Tests: set / get Roundtrip
# ---------------------------------------------------------------------------


class TestSetGet:
    def test_roundtrip_simple(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("my_key", "my_value")
        assert storage.get("my_key") == "my_value"

    def test_roundtrip_api_key(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("deepl_api_key", "edd401e9-6db5-4b14-b3fb-cf593de8c6d2:fx")
        result = storage.get("deepl_api_key")
        assert result == "edd401e9-6db5-4b14-b3fb-cf593de8c6d2:fx"

    def test_multiple_keys(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("key_a", "value_a")
        storage.set("key_b", "value_b")
        assert storage.get("key_a") == "value_a"
        assert storage.get("key_b") == "value_b"

    def test_overwrite_existing_key(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("url", "http://localhost:11434")
        storage.set("url", "http://localhost:9999")
        assert storage.get("url") == "http://localhost:9999"

    def test_missing_key_returns_default(self, isolated_storage):
        storage, _, _ = isolated_storage
        result = storage.get("nonexistent", default="fallback")
        assert result == "fallback"

    def test_missing_key_returns_none_default(self, isolated_storage):
        storage, _, _ = isolated_storage
        assert storage.get("nonexistent") is None

    def test_unicode_value(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("label", "Übersetzung: Ärger mit Öl")
        assert storage.get("label") == "Übersetzung: Ärger mit Öl"


# ---------------------------------------------------------------------------
# Tests: Verschlüsselung prüfen (raw != Klartext)
# ---------------------------------------------------------------------------


class TestEncryptionOnDisk:
    def test_raw_file_is_not_plaintext(self, isolated_storage):
        storage, store_file, _ = isolated_storage
        storage.set("secret", "my-secret-value")
        raw = store_file.read_bytes()
        # Klartext darf nicht in der Datei erscheinen
        assert b"my-secret-value" not in raw

    def test_raw_file_is_not_json(self, isolated_storage):
        storage, store_file, _ = isolated_storage
        storage.set("key", "value")
        raw = store_file.read_bytes()
        # Rohdatei ist kein valides JSON (verschlüsselt)
        with pytest.raises(Exception):
            json.loads(raw)

# test_salt_file_created entfernt (Subtask 2, Option A nach Reflexions-Regel 1):
# Implementation-Detail-Test der alten Welt — Salt-File wird nach Subtask 2
# nicht mehr vom SecureStorage-Pfad erzeugt (DEK kommt via HKDF aus
# KeyManager, nicht via PBKDF2-mit-Salt). Salt-File-Verifikation fuer den
# Subtask-3-Bestandsdaten-Migrations-Pfad bekommt eigene Tests laut
# MIGRATION_TEST_PLAN §3.7 (SM-1..SM-4). Verschluesselungs-Garantie wird
# weiterhin durch test_raw_file_is_not_plaintext geprueft — der Test, der
# wirklich zaehlt.


# ---------------------------------------------------------------------------
# Tests: delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_existing_key(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("to_delete", "some_value")
        storage.delete("to_delete")
        assert storage.get("to_delete") is None

    def test_delete_nonexistent_key_no_error(self, isolated_storage):
        storage, _, _ = isolated_storage
        # Soll keinen Fehler werfen
        storage.delete("does_not_exist")

    def test_delete_only_removes_target_key(self, isolated_storage):
        storage, _, _ = isolated_storage
        storage.set("keep", "important")
        storage.set("remove", "trash")
        storage.delete("remove")
        assert storage.get("keep") == "important"
        assert storage.get("remove") is None


# ---------------------------------------------------------------------------
# Tests: Fehlerverhalten
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_corrupted_store_returns_default(self, isolated_storage):
        storage, store_file, _ = isolated_storage
        storage.set("key", "value")
        # Datei korrumpieren
        store_file.write_bytes(b"CORRUPTED_DATA_NOT_FERNET")
        # Sollte keinen Exception werfen, sondern Default zurückgeben
        result = storage.get("key", default="safe_default")
        assert result == "safe_default"

    def test_is_available_true(self, isolated_storage):
        storage, _, _ = isolated_storage
        assert storage.is_available is True


# ---------------------------------------------------------------------------
# Corruption-Observer-Pattern (Recovery-UX)
# ---------------------------------------------------------------------------


class TestFalsePositiveBackup:
    """ Forensik-Befund 2026-05-12: das alte ``not data``-Check
    in ``set`` hat ein legitimes leeres Dict (``{}``) als Korruption
    eingestuft und das File unnoetig gebackupt. Diese Tests verhindern
    die Rueckkehr des Bugs."""

    def test_set_does_not_backup_legitimately_empty_store(
        self, isolated_storage, tmp_path
    ):
        """Ein legitimes leeres Dict ({}) im Store darf NICHT als
        Korruption gewertet werden. Der Bug aus 2026-05-12: Subtask-3-
        Migration hat MIGRATED_EMPTY → {} geschrieben, naechstes set
        hat das gebackupt obwohl der File perfekt lesbar war."""
        storage, store_file, _ = isolated_storage
        # Direkt ein legitimes {} mit dem Fernet-Key schreiben — simuliert
        # das was migrate_secure_store fuer MIGRATED_EMPTY tut.
        empty_encrypted = storage._fernet.encrypt(b"{}")
        store_file.write_bytes(empty_encrypted)
        assert store_file.stat().st_size > 0

        # Set einen neuen Key — sollte den Store-Inhalt mergen, nicht backupen
        storage.set("new_key", "new_value")

        # Es darf KEIN.bak_* File angelegt worden sein
        baks = list(store_file.parent.glob("*.bak_*"))
        assert baks == [], f"Unexpected backup files: {baks}"

        # Und der gemergte Inhalt ist da
        assert storage.get("new_key") == "new_value"

    def test_set_does_backup_real_corruption(self, isolated_storage):
        """Echtes InvalidToken (Fremd-Key) → Backup MUSS ausgeloest werden."""
        storage, store_file, _ = isolated_storage
        from cryptography.fernet import Fernet  # noqa: PLC0415

        # Mit Fremd-Key verschluesseln — echter InvalidToken-Trigger
        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"x": 1}'))

        storage.set("recovery_key", "recovery_value")

        # Jetzt MUSS ein.bak_* angelegt sein
        baks = list(store_file.parent.glob("*.bak_*"))
        assert len(baks) == 1, f"Expected 1 backup, got: {baks}"


class TestCorruptionObserver:
    """``add_corruption_observer`` + ``_emit_corruption_event``.

    Recovery-UX: bei DPAPI-Drift (R-8) zeigt MainWindow einen Dialog.
    Der Observer-Hook ist Qt-frei in core/security/encryption.py.
    """

    def test_observer_fires_on_invalidtoken_with_nonempty_file(
        self, isolated_storage
    ):
        """Wenn _load_all auf eine nicht-leere Datei mit InvalidToken
        trifft, wird der Observer mit (corrupted_path, None) gerufen."""
        storage, store_file, _ = isolated_storage
        # Erst echte Daten schreiben (entschluesselbar)
        storage.set("api_key", "verify-roundtrip")
        # Datei manuell mit Fernet-Token korrumpieren — der Token sieht
        # wie ein valider Fernet-Token aus, ist aber mit anderem Key
        # signiert. Trigger fuer InvalidToken.
        from cryptography.fernet import Fernet  # noqa: PLC0415

        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"some": "data"}'))

        events: list[tuple] = []
        storage.add_corruption_observer(lambda path, bak: events.append((path, bak)))

        # _load_all triggert die Detection
        storage.get("api_key")

        assert len(events) == 1
        assert events[0][0] == store_file
        assert events[0][1] is None  # noch kein Backup beim Read

    def test_observer_does_not_fire_on_missing_file(self, isolated_storage):
        """Wenn secure_store.enc nicht existiert, kein Corruption-Event."""
        storage, store_file, _ = isolated_storage
        # Sicherheitshalber loeschen falls eine vorherige Operation
        # die Datei angelegt hat
        if store_file.exists():
            store_file.unlink()

        events: list[tuple] = []
        storage.add_corruption_observer(lambda path, bak: events.append((path, bak)))

        storage.get("never_set")

        assert events == []

    def test_observer_does_not_fire_on_empty_file(self, isolated_storage):
        """Leeres File ist kein Corruption-Symptom — kein Event."""
        storage, store_file, _ = isolated_storage
        store_file.write_bytes(b"")  # 0 bytes

        events: list[tuple] = []
        storage.add_corruption_observer(lambda path, bak: events.append((path, bak)))

        storage.get("anything")

        assert events == []

    def test_observer_fires_only_once_across_multiple_reads(
        self, isolated_storage
    ):
        """Wiederholtes _load_all auf korruptem File feuert Observer
        nur EINMAL — Idempotenz."""
        storage, store_file, _ = isolated_storage
        from cryptography.fernet import Fernet  # noqa: PLC0415

        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"x": 1}'))

        events: list[tuple] = []
        storage.add_corruption_observer(lambda path, bak: events.append((path, bak)))

        # Drei Reads in Folge
        storage.get("a")
        storage.get("b")
        storage.get("c")

        assert len(events) == 1

    def test_observer_re_emitted_after_backup_with_path(self, isolated_storage):
        """Nach erfolgreichem _backup_corrupted_store wird der Observer
        nochmal aufgerufen — diesmal mit dem konkreten Backup-Pfad. Damit
        kann der Recovery-Dialog den Sicherungs-Pfad anzeigen."""
        storage, store_file, _ = isolated_storage
        from cryptography.fernet import Fernet  # noqa: PLC0415

        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"x": 1}'))

        events: list[tuple] = []
        storage.add_corruption_observer(lambda path, bak: events.append((path, bak)))

        # Erst ein get triggert das erste Event (backup=None)
        storage.get("anything")
        assert len(events) == 1
        assert events[0][1] is None

        # set triggert _backup_corrupted_store → zweites Event mit Backup-Pfad
        storage.set("new_key", "new_value")

        assert len(events) == 2
        assert events[1][1] is not None
        # Backup-Pfad muss Pattern.bak_YYYYMMDD_HHMMSS haben
        assert ".bak_" in events[1][1].name

    def test_multiple_observers_all_called(self, isolated_storage):
        """Mehrere registrierte Observer werden alle gerufen, in
        Reihenfolge der Registrierung."""
        storage, store_file, _ = isolated_storage
        from cryptography.fernet import Fernet  # noqa: PLC0415

        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"x": 1}'))

        events_a: list[tuple] = []
        events_b: list[tuple] = []
        storage.add_corruption_observer(lambda p, b: events_a.append((p, b)))
        storage.add_corruption_observer(lambda p, b: events_b.append((p, b)))

        storage.get("anything")

        assert len(events_a) == 1
        assert len(events_b) == 1

    def test_observer_exception_isolated(self, isolated_storage):
        """Ein Observer der Exception wirft, soll SecureStorage nicht
        crashen — und der NACHFOLGENDE Observer in der Liste soll
        trotzdem aufgerufen werden."""
        storage, store_file, _ = isolated_storage
        from cryptography.fernet import Fernet  # noqa: PLC0415

        other_key = Fernet.generate_key()
        store_file.write_bytes(Fernet(other_key).encrypt(b'{"x": 1}'))

        def bad_observer(path, bak):
            raise RuntimeError("observer-bug")

        good_events: list[tuple] = []
        storage.add_corruption_observer(bad_observer)
        storage.add_corruption_observer(
            lambda p, b: good_events.append((p, b))
        )

        # Darf nicht raisen
        result = storage.get("any_key", default="fallback")
        assert result == "fallback"
        # Zweiter Observer muss trotzdem aufgerufen worden sein
        assert len(good_events) == 1


# Hinweis: die ``TestGetIntegrityKeyDeprecation``-
# Klasse wurde mit dem Loeschen von ``get_integrity_key`` entfernt.
# Die Migration-only-Replikation lebt jetzt privat in
# ``core.database.migrate_to_envelope._derive_legacy_integrity_key``.


# ---------------------------------------------------------------------------
#fail-closed: SecureStorageUnavailableError bei Init-Sicherheits-
# Indikator (DPAPI-Drift, KeyManager-Korruption). set/get/delete werfen
# RuntimeError statt stiller False/None/no-op.
# ---------------------------------------------------------------------------


class TestFailClosedOnInitError:
    """"Verschluesselung fail-closed: RuntimeError wenn Schluessel
    fehlt, kein Klartext-Fallback" — siehe P0-2 aus Code-Review 2026-05-19."""

    def _make_failing_storage(self, monkeypatch, err: Exception):
        """Erstellt SecureStorage-Instanz mit gemocktem fehlschlagendem KeyManager."""
        import core.security.encryption as enc_mod

        class _FailingKM:
            def derive_secondary_key(self, _purpose: str) -> bytes:
                raise err

        return enc_mod.SecureStorage(key_manager=_FailingKM())

    def test_init_error_set_on_keymanager_failure(self, monkeypatch):
        from core.database.key_manager import KeyManagerError

        err = KeyManagerError("DPAPI-Drift simuliert")
        storage = self._make_failing_storage(monkeypatch, err)

        assert storage.is_available is False
        assert storage.init_error is err

    def test_init_error_none_on_success(self, isolated_storage):
        storage, _, _ = isolated_storage
        assert storage.init_error is None

    def test_set_raises_on_init_error(self, monkeypatch):
        from core.database.key_manager import KeyManagerError
        from core.security.encryption import SecureStorageUnavailableError

        err = KeyManagerError("DPAPI-Drift simuliert")
        storage = self._make_failing_storage(monkeypatch, err)

        with pytest.raises(SecureStorageUnavailableError) as exc_info:
            storage.set("any_key", "any_value")
        assert exc_info.value.__cause__ is err

    def test_get_raises_on_init_error(self, monkeypatch):
        from core.database.key_manager import KeyManagerError
        from core.security.encryption import SecureStorageUnavailableError

        err = KeyManagerError("DPAPI-Drift simuliert")
        storage = self._make_failing_storage(monkeypatch, err)

        with pytest.raises(SecureStorageUnavailableError) as exc_info:
            storage.get("any_key", default="fallback")
        assert exc_info.value.__cause__ is err

    def test_delete_raises_on_init_error(self, monkeypatch):
        from core.database.key_manager import KeyManagerError
        from core.security.encryption import SecureStorageUnavailableError

        err = KeyManagerError("DPAPI-Drift simuliert")
        storage = self._make_failing_storage(monkeypatch, err)

        with pytest.raises(SecureStorageUnavailableError):
            storage.delete("any_key")

    def test_unavailable_error_is_runtime_error(self):
        from core.security.encryption import SecureStorageUnavailableError

        assert issubclass(SecureStorageUnavailableError, RuntimeError)
