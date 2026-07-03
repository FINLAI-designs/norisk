"""Tests für ``core.first_run_wizard.trigger.needs_first_run``."""

from __future__ import annotations

import json
from pathlib import Path

from core.first_run_wizard.trigger import adopt_legacy_users, needs_first_run


def test_missing_users_file_triggers_wizard(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    assert needs_first_run(users_file=target) is True


def test_empty_users_file_triggers_wizard(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    target.write_text("{}", encoding="utf-8")
    assert needs_first_run(users_file=target) is True


def test_only_placeholder_admin_triggers_wizard(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    target.write_text(
        json.dumps(
            {
                "admin": {
                    "username": "admin",
                    "password_hash": "",
                    "role": "admin",
                    "full_name": "Administrator",
                    "requires_setup": True,
                }
            }
        ),
        encoding="utf-8",
    )
    assert needs_first_run(users_file=target) is True


def test_real_user_skips_wizard(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    target.write_text(
        json.dumps(
            {
                "patrick": {
                    "username": "patrick",
                    "password_hash": "$2b$12$somehashvalue",
                    "role": "admin",
                    "full_name": "Patrick",
                }
            }
        ),
        encoding="utf-8",
    )
    assert needs_first_run(users_file=target) is False


def test_placeholder_plus_real_user_skips_wizard(tmp_path: Path) -> None:
    """Nach dem Wizard kann der alte Placeholder noch da sein — egal."""
    target = tmp_path / "users.json"
    target.write_text(
        json.dumps(
            {
                "admin": {
                    "username": "admin",
                    "password_hash": "",
                    "role": "admin",
                    "full_name": "Administrator",
                    "requires_setup": True,
                },
                "patrick": {
                    "username": "patrick",
                    "password_hash": "$2b$12$somehashvalue",
                    "role": "admin",
                    "full_name": "Patrick",
                },
            }
        ),
        encoding="utf-8",
    )
    assert needs_first_run(users_file=target) is False


def test_corrupt_json_triggers_wizard(tmp_path: Path) -> None:
    target = tmp_path / "users.json"
    target.write_text("not { valid json", encoding="utf-8")
    assert needs_first_run(users_file=target) is True


# ──: App-Marker-Filter ────────────────────────────────────────────────


def _write_user(tmp_path: Path, *, created_by_app: str | None) -> Path:
    """Schreibt eine users.json mit einem echten User (Passwort gesetzt)."""
    user: dict[str, object] = {
        "username": "patrick",
        "password_hash": "$2b$12$somehashvalue",
        "role": "admin",
        "full_name": "Patrick",
    }
    if created_by_app is not None:
        user["created_by_app"] = created_by_app
    target = tmp_path / "users.json"
    target.write_text(json.dumps({"patrick": user}), encoding="utf-8")
    return target


def test_app_id_none_ist_legacy_verhalten(tmp_path: Path) -> None:
    """Ohne app_id zaehlt jeder User mit Passwort — auch ohne Marker."""
    target = _write_user(tmp_path, created_by_app=None)
    assert needs_first_run(users_file=target, app_id=None) is False


def test_passender_marker_skippt_wizard(tmp_path: Path) -> None:
    target = _write_user(tmp_path, created_by_app="norisk")
    assert needs_first_run(users_file=target, app_id="norisk") is False


def test_fremder_marker_erzwingt_wizard(tmp_path: Path) -> None:
    target = _write_user(tmp_path, created_by_app="sibling_app")
    assert needs_first_run(users_file=target, app_id="norisk") is True


def test_fehlender_marker_mit_app_id_erzwingt_wizard(tmp_path: Path) -> None:
    """Pre--User ohne Marker zaehlen unter app_id-Filter als fremd."""
    target = _write_user(tmp_path, created_by_app=None)
    assert needs_first_run(users_file=target, app_id="norisk") is True


# ---------------------------------------------------------------------------
# B-STAR — adopt_legacy_users (Legacy-User ohne created_by_app-Marker)
# ---------------------------------------------------------------------------


def _legacy_real_user(**override: object) -> dict:
    """Real-User (gesetztes Passwort, kein requires_setup), per Default ohne Marker."""
    user = {
        "username": "chef",
        "password_hash": "$2b$12$somehashvalue",
        "role": "admin",
        "full_name": "Chef",
        "requires_setup": False,
    }
    user.update(override)
    return user


def _write_users(target: Path, users: dict) -> None:
    target.write_text(json.dumps(users), encoding="utf-8")


def test_adopt_legacy_user_with_db_data(tmp_path: Path) -> None:
    """Unmarkierter Legacy-User + eigene DB-Daten → adoptiert, kein Wizard mehr."""
    users = tmp_path / "users.json"
    _write_users(users, {"chef": _legacy_real_user()})
    db = tmp_path / "db"
    db.mkdir()
    (db / "norisk_main.db").write_bytes(b"x")

    assert needs_first_run(users_file=users, app_id="norisk") is True
    assert adopt_legacy_users("norisk", users_file=users, db_dir=db) == 1
    assert needs_first_run(users_file=users, app_id="norisk") is False
    data = json.loads(users.read_text(encoding="utf-8"))
    assert data["chef"]["created_by_app"] == "norisk"


def test_adopt_skipped_without_db_data(tmp_path: Path) -> None:
    """Ohne DB-Bestandsdaten → keine Adoption (echte Ersteinrichtung)."""
    users = tmp_path / "users.json"
    _write_users(users, {"chef": _legacy_real_user()})
    db = tmp_path / "db"
    db.mkdir()
    assert adopt_legacy_users("norisk", users_file=users, db_dir=db) == 0
    assert needs_first_run(users_file=users, app_id="norisk") is True


def test_adopt_skipped_with_foreign_marker(tmp_path: Path) -> None:
    """Fremd-App-Marker vorhanden → keine Adoption (Multi-App-Maschine)."""
    users = tmp_path / "users.json"
    _write_users(
        users,
        {
            "chef": _legacy_real_user(),
            "sen": _legacy_real_user(username="sen", created_by_app="sibling_app"),
        },
    )
    db = tmp_path / "db"
    db.mkdir()
    (db / "norisk_main.db").write_bytes(b"x")
    assert adopt_legacy_users("norisk", users_file=users, db_dir=db) == 0
    data = json.loads(users.read_text(encoding="utf-8"))
    assert data["chef"].get("created_by_app", "") == ""


def test_adopt_noop_when_only_setup_admin(tmp_path: Path) -> None:
    """Kein Real-User (nur Setup-Admin) → nichts zu adoptieren, Wizard bleibt."""
    users = tmp_path / "users.json"
    _write_users(
        users,
        {"admin": {"username": "admin", "password_hash": "", "requires_setup": True}},
    )
    db = tmp_path / "db"
    db.mkdir()
    (db / "norisk_main.db").write_bytes(b"x")
    assert adopt_legacy_users("norisk", users_file=users, db_dir=db) == 0
    assert needs_first_run(users_file=users, app_id="norisk") is True


def test_adopt_idempotent_when_already_marked(tmp_path: Path) -> None:
    """Bereits korrekt markiert → No-op (idempotent)."""
    users = tmp_path / "users.json"
    _write_users(users, {"chef": _legacy_real_user(created_by_app="norisk")})
    db = tmp_path / "db"
    db.mkdir()
    (db / "norisk_main.db").write_bytes(b"x")
    assert adopt_legacy_users("norisk", users_file=users, db_dir=db) == 0
