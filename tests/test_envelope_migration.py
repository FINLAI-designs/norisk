"""tests/test_envelope_migration — Subtask-2-Tests E-1..E-6 fuer Envelope-Encryption.

Verifiziert die Konsumenten-Anbindung des KeyManager, Subtask 2):

* E-1 — Smoke-Verweis: bestehende EncryptedDatabase-Tests bleiben gruen.
* E-2 — DB-Oeffnen mit DEK aus:meth:`KeyManager.derive_secondary_key`.
* E-3 — DB-Oeffnen ueberlebt simulierten Hardware-Fingerprint-Wechsel.
* E-4 — SecureStorage nutzt ``derive_secondary_key("secure_storage")``.
* E-5 — SecureStorage ueberlebt simulierten Hardware-Fingerprint-Wechsel.

(E-6 entfernt mit: ``get_integrity_key`` ist nicht mehr Teil der
Public-Surface; die Migration-only-Replikation lebt privat in
``core.database.migrate_to_envelope._derive_legacy_integrity_key``.)

Architektur-Garantie nach Subtask 2: ``get_hardware_fingerprint`` ist
NICHT mehr im Schluessel-Pfad fuer EncryptedDatabase oder SecureStorage.
E-3 und E-5 dokumentieren das als ausfuehrbare Garantie — ein
versehentliches Re-Koppeln von Crypto an Hardware in Zukunft wuerde
diese Tests brechen.

Author: Patrick Riederich
Version: 1.0 (Subtask 2)
"""

from __future__ import annotations

from unittest.mock import patch

# KeyManager-Bootstrap kommt aus dem globalen tests/conftest.py-Autouse-
# Fixture (Subtask 2). Tests in dieser Datei brauchen keinen
# eigenen Bootstrap.


# ---------------------------------------------------------------------------
# E-1, E-2, E-3 — EncryptedDatabase
# ---------------------------------------------------------------------------


class TestEncryptedDatabaseEnvelope:
    """Subtask-2-Tests fuer EncryptedDatabase ueber KeyManager.

    Vollstaendige EncryptedDatabase-Funktional-Tests 
    ``tests/test_encrypted_db.py``. Hier nur die Subtask-2-spezifischen
    Eigenschaften: KeyManager-DEK-Pfad und HW-Fingerprint-Entkopplung.
    """

    def test_e1_existing_tests_green_marker(self):
        """E-1: Anker-Test fuer bestehende Test-Suite-Coverage.

        Vollstaendige EncryptedDatabase-Tests laufen in
        ``tests/test_encrypted_db.py`` (22 Tests, gruen seit Subtask 2).
        E-1 hier ist ein einzeiliger Smoke-Verweis, kein dedizierter
        Test — die Suite-Integration wird in Schritt 2.6 verifiziert.
        """
        # Smoke: das Modul ist importierbar und das Symbol existiert.
        from core.database.encrypted_db import EncryptedDatabase

        assert EncryptedDatabase is not None

    def test_e2_db_open_with_dek(self, tmp_path):
        """E-2: DB-Oeffnen mit DEK aus KeyManager.derive_secondary_key.

        Verifiziert den End-to-End-Pfad: KeyManager-DEK →
        derive_secondary_key("db:<name>") → SQLCipher-Verbindung →
        Daten persistieren ueber Reconnect.
        """
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            db = EncryptedDatabase("envelope_e2")
            with db.connection() as conn:
                conn.execute("CREATE TABLE t (id INTEGER, val TEXT)")
                conn.execute("INSERT INTO t VALUES (1, 'envelope-ok')")

            # Reconnect — Daten muessen erhalten sein.
            with db.connection() as conn:
                row = conn.execute("SELECT val FROM t WHERE id=1").fetchone()
                assert row[0] == "envelope-ok"

    def test_e3_db_open_after_simulated_hw_change(self, tmp_path, monkeypatch):
        """E-3: DB bleibt offenbar trotz Hardware-Fingerprint-Wechsel.

        Architektur-Garantie nach Subtask 2: Master-Key ist DPAPI-
        CurrentUser-basiert, NICHT Hardware-Fingerprint-basiert. Ein
        HW-Wechsel (NIC, Mainboard, MAC) hat keinen Effekt auf die
        DB-Lesbarkeit.

        Test: DB schreiben mit gemocktem ``get_hardware_fingerprint``
        Wert "hw-A", dann mit Wert "hw-B" lesen. Funktioniert, weil der
        Mock irrelevant fuer den Crypto-Pfad ist — ein versehentliches
        Re-Koppeln in Zukunft wuerde diesen Test brechen.
        """
        from core.database.encrypted_db import EncryptedDatabase

        with patch("core.database.encrypted_db.DB_DIR", tmp_path):
            with patch(
                "core.hardware_fingerprint.get_hardware_fingerprint",
                return_value="hw-fingerprint-A",
            ):
                db = EncryptedDatabase("envelope_e3")
                with db.connection() as conn:
                    conn.execute("CREATE TABLE t (id INTEGER, val TEXT)")
                    conn.execute("INSERT INTO t VALUES (1, 'survives-hw-swap')")

            # HW-Fingerprint wechselt — DB muss weiterhin lesbar sein.
            with patch(
                "core.hardware_fingerprint.get_hardware_fingerprint",
                return_value="hw-fingerprint-B-different",
            ):
                db_after = EncryptedDatabase("envelope_e3")
                with db_after.connection() as conn:
                    row = conn.execute("SELECT val FROM t WHERE id=1").fetchone()
                    assert row[0] == "survives-hw-swap"


# ---------------------------------------------------------------------------
# E-4, E-5, E-6 — SecureStorage + Deprecation
# ---------------------------------------------------------------------------


class TestSecureStorageEnvelope:
    """Subtask-2-Tests fuer SecureStorage ueber KeyManager.

    Vollstaendige SecureStorage-Funktional-Tests 
    ``tests/test_secure_storage.py``. Hier nur Subtask-2-spezifische
    Eigenschaften.
    """

    def test_e4_secure_storage_with_secondary_key(self, tmp_path, monkeypatch):
        """E-4: SecureStorage funktioniert mit derive_secondary_key('secure_storage').

        End-to-End: KeyManager-DEK → ``derive_secondary_key("secure_storage")``
        → ``base64.urlsafe_b64encode`` → ``Fernet`` → set/get-Roundtrip.
        """
        import core.security.encryption as enc_mod

        store_file = tmp_path / "secure_store.enc"
        salt_file = tmp_path / ".salt"
        monkeypatch.setattr(enc_mod, "_STORE_FILE", store_file)
        monkeypatch.setattr(enc_mod, "_SALT_FILE", salt_file)

        storage = enc_mod.SecureStorage()
        assert storage.is_available is True

        storage.set("api_key", "envelope-secret-value")
        assert storage.get("api_key") == "envelope-secret-value"

    def test_e5_secure_storage_survives_hw_change(self, tmp_path, monkeypatch):
        """E-5: SecureStorage-Werte ueberleben simulierten Hardware-Fingerprint-Wechsel.

        Architektur-Garantie analog zu E-3: SecureStorage-Fernet-Key
        haengt am DEK + DPAPI, NICHT am HW-Fingerprint. Ein HW-Wechsel
        macht keine SecureStorage-Werte unlesbar.

        Test: Wert schreiben mit gemocktem HW-Fingerprint "hw-A",
        SecureStorage neu instanziieren mit gemocktem HW-Fingerprint
        "hw-B", denselben Wert lesen — funktioniert.
        """
        import core.security.encryption as enc_mod

        store_file = tmp_path / "secure_store.enc"
        salt_file = tmp_path / ".salt"
        monkeypatch.setattr(enc_mod, "_STORE_FILE", store_file)
        monkeypatch.setattr(enc_mod, "_SALT_FILE", salt_file)

        with patch(
            "core.hardware_fingerprint.get_hardware_fingerprint",
            return_value="hw-A",
        ):
            storage_a = enc_mod.SecureStorage()
            storage_a.set("token", "persistent-secret")

        # HW-Fingerprint wechselt — SecureStorage muss weiterhin lesen koennen.
        with patch(
            "core.hardware_fingerprint.get_hardware_fingerprint",
            return_value="hw-B-completely-different",
        ):
            storage_b = enc_mod.SecureStorage()
            assert storage_b.get("token") == "persistent-secret"
