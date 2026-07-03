"""Tests für:class:`core.first_run_wizard.pages.recovery_code_page`."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from core.auth.recovery_code import is_valid_format, verify_recovery_code  # noqa: E402
from core.auth.user_store import UserStore  # noqa: E402
from core.first_run_wizard.pages.recovery_code_page import (  # noqa: E402
    RecoveryCodeDisplayPage,
)


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> UserStore:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    finlai_dir = fake_home / ".finlai"
    users_file = finlai_dir / "users.json"
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", finlai_dir)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", users_file)
    store = UserStore()
    store.create_user(
        username="patrick",
        password="initial1",
        role="admin",
        full_name="Patrick",
        allowed_tools=[],
        first_name="Patrick",
        email="patrick@example.com",
    )
    return store


def test_page_generates_valid_code(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    assert is_valid_format(page._code)
    assert page._code_label.text() == page._code


def test_page_not_complete_without_checkbox(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    assert page.is_complete() is False


def test_page_complete_after_checkbox(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    page._confirm_checkbox.setChecked(True)
    assert page.is_complete() is True


def test_commit_without_username_raises(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    with pytest.raises(RuntimeError):
        page.commit()


def test_commit_persists_hash(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    page.set_username("patrick")
    code = page._code  # vor commit sichern

    page.commit()

    user = isolated_store.get_user("patrick")
    assert user is not None
    assert user.recovery_code_hash.startswith("$2")
    assert verify_recovery_code(code, user.recovery_code_hash) is True


def test_commit_is_idempotent(
    qapp,  # noqa: ARG001
    isolated_store: UserStore,
) -> None:
    page = RecoveryCodeDisplayPage(user_store=isolated_store)
    page.set_username("patrick")
    page.commit()
    first_hash = isolated_store.get_user("patrick").recovery_code_hash
    page.commit()  # zweiter Aufruf soll nichts ändern
    second_hash = isolated_store.get_user("patrick").recovery_code_hash
    assert first_hash == second_hash
