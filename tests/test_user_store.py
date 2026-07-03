"""
test_user_store — Tests für die update_user Allowlist und set_role/change_password.

Prüft:
- update_user blockiert sensible Felder (role, password_hash)
- update_user akzeptiert erlaubte Felder
- change_password erzwingt Mindestlänge
- set_role validiert die Rolle

Author: Patrick Riederich
"""

import pytest

from core.auth.user_store import UserStore

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """Isolierter UserStore mit temporären Dateipfaden."""
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", tmp_path)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", tmp_path / "users.json")
    return UserStore()


# ---------------------------------------------------------------------------
# update_user Allowlist
# ---------------------------------------------------------------------------


def test_update_user_allowlist(store):
    """update_user darf role und password_hash nicht akzeptieren."""
    with pytest.raises(ValueError, match="Nicht erlaubte"):
        store.update_user("admin", role="admin", password_hash="x")


def test_update_user_erlaubte_felder(store):
    """update_user akzeptiert display_name ohne Fehler."""
    store.update_user("admin", display_name="Test Admin")


def test_update_user_full_name_erlaubt(store):
    """update_user akzeptiert full_name (rückwärtskompatibel)."""
    updated = store.update_user("admin", full_name="Super Admin")
    assert updated.full_name == "Super Admin"


def test_update_user_is_active_erlaubt(store):
    """update_user akzeptiert is_active."""
    store.update_user("admin", is_active=False)
    data = store._load()
    assert data["admin"]["is_active"] is False


def test_update_user_role_verboten(store):
    """role darf nicht über update_user geändert werden."""
    with pytest.raises(ValueError, match="Nicht erlaubte"):
        store.update_user("admin", role="user")


def test_update_user_password_hash_verboten(store):
    """password_hash darf nicht über update_user geändert werden."""
    with pytest.raises(ValueError, match="Nicht erlaubte"):
        store.update_user("admin", password_hash="fake_hash")


def test_update_user_unbekannter_user(store):
    """update_user wirft KeyError bei unbekanntem User."""
    with pytest.raises(KeyError, match="nicht gefunden"):
        store.update_user("nobody", full_name="X")


# ---------------------------------------------------------------------------
# change_password Mindestlänge
# ---------------------------------------------------------------------------


def test_change_password_zu_kurz(store):
    """change_password wirft ValueError wenn new_pw < 8 Zeichen."""
    store.complete_setup("admin", "Sicher!2026#")
    with pytest.raises(ValueError, match="zu kurz"):
        store.change_password("admin", "Sicher!2026#", "kurz")


def test_set_password_admin_zu_kurz(store):
    """set_password_admin wirft ValueError wenn new_pw < 8 Zeichen."""
    with pytest.raises(ValueError, match="zu kurz"):
        store.set_password_admin("admin", "kurz")


# ---------------------------------------------------------------------------
# set_role
# ---------------------------------------------------------------------------


def test_set_role_aendert_rolle(store):
    """set_role ändert die Rolle korrekt."""
    store.create_user("testuser", "passw0rd!", "user", "Test", [])
    store.set_role("testuser", "admin")
    users = {u.username: u for u in store.get_all_users()}
    assert users["testuser"].role == "admin"


def test_set_role_ungueltige_rolle(store):
    """set_role wirft ValueError bei ungültiger Rolle."""
    with pytest.raises(ValueError, match="Ungültige Rolle"):
        store.set_role("admin", "superadmin")


def test_set_role_unbekannter_user(store):
    """set_role wirft ValueError bei unbekanntem User."""
    with pytest.raises(ValueError, match="nicht gefunden"):
        store.set_role("nobody", "user")


# ---------------------------------------------------------------------------
# Setup-Flow
# ---------------------------------------------------------------------------


def test_requires_setup_bei_leerem_hash(store):
    """Neuer Admin ohne Passwort erfordert Setup."""
    assert store.requires_password_setup("admin") is True


def test_complete_setup_schwaches_pw(store):
    """complete_setup wirft ValueError bei zu schwachem Passwort."""
    with pytest.raises(ValueError):
        store.complete_setup("admin", "kurz")


def test_complete_setup_erfolgreich(store):
    """complete_setup setzt Passwort und löscht Setup-Flag."""
    store.complete_setup("admin", "Sicher!2026#")
    assert store.requires_password_setup("admin") is False
    assert store.authenticate("admin", "Sicher!2026#") is not None


def test_requires_setup_unbekannter_user(store):
    """requires_password_setup gibt False zurück für unbekannten User."""
    assert store.requires_password_setup("nobody") is False


# ---------------------------------------------------------------------------
# Backup-Rotation
# ---------------------------------------------------------------------------


def test_save_erzeugt_backup(store, tmp_path):
    """Jeder _save kopiert die bestehende users.json als Backup."""
    store.create_user("u1", "Passwort1!", "user", "User 1", [])
    backups = list(tmp_path.glob("users.json.bak.*"))
    assert len(backups) >= 1


def test_backup_rotation_haelt_max_fuenf(store, tmp_path):
    """Nach vielen Schreibvorgaengen bleiben maximal 5 Backups."""
    for i in range(10):
        store.update_user("admin", full_name=f"Admin {i}")
    backups = list(tmp_path.glob("users.json.bak.*"))
    assert len(backups) <= 5


def test_restore_aus_backup_moeglich(store, tmp_path):
    """Nach Loeschen von users.json laesst sich ein User aus einem Backup rekonstruieren.

    Backups sind Pre-Write-Snapshots — nach zwei aufeinanderfolgenden
    Schreibvorgaengen enthaelt das neueste Backup den Zustand *vor*
    dem letzten Save, also mit dem zuerst angelegten User.
    """
    import time as _time

    store.create_user("restore_me", "Passwort1!", "user", "Restore Me", [])
    _time.sleep(1.1)  # unterschiedliche Backup-Timestamps erzwingen
    store.update_user("restore_me", full_name="Restored")

    users_file = tmp_path / "users.json"
    users_file.unlink()

    backups = sorted(
        tmp_path.glob("users.json.bak.*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    assert backups, "Backup muss existieren"
    import json as _json

    latest = _json.loads(backups[0].read_text(encoding="utf-8"))
    assert "restore_me" in latest


def test_init_warnt_bei_vorhandenen_backups(tmp_path, monkeypatch, caplog):
    """UserStore loggt WARNING wenn users.json fehlt aber Backups existieren."""
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", tmp_path)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", tmp_path / "users.json")
    (tmp_path / "users.json.bak.20260420_120000").write_text("{}", encoding="utf-8")
    import logging

    with caplog.at_level(logging.WARNING, logger="core.auth.user_store"):
        UserStore()
    assert any("Backup" in r.message for r in caplog.records)
