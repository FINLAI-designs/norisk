"""End-to-End-Test des First-Run-Wizards."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from core.auth.user_store import UserStore  # noqa: E402
from core.first_run_wizard.wizard import FirstRunWizard  # noqa: E402

pytestmark = pytest.mark.gui


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    finlai_dir = fake_home / ".finlai"
    users_file = finlai_dir / "users.json"
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", finlai_dir)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", users_file)
    return fake_home


def test_wizard_navigates_and_completes(
    qapp,  # noqa: ARG001
    isolated_home: Path,  # noqa: ARG001
) -> None:
    wizard = FirstRunWizard(app_name="NoRisk by FINLAI")

    # Start: Welcome (Index 0), „Weiter" ist aktiv (Welcome is_complete == True).
    assert wizard._stack.currentIndex() == 0
    assert wizard._btn_next.isEnabled() is True

    wizard._on_next()  # → AdminSetup
    assert wizard._stack.currentIndex() == 1

    # AdminSetup ohne Input → „Weiter" disabled
    assert wizard._btn_next.isEnabled() is False

    # Gültige Eingabe
    admin = wizard._admin_setup
    admin._first_name.setText("Patrick")
    admin._username.setText("patrick")
    admin._email.setText("patrick@example.com")
    admin._full_name.setText("Patrick Riederich")
    admin._password.setText("geheim12")
    admin._password_repeat.setText("geheim12")
    assert wizard._btn_next.isEnabled() is True

    wizard._on_next()  # → CompanyScoping, optional)
    assert wizard._stack.currentIndex() == 2

    # User wurde bei AdminSetup angelegt
    user = UserStore().get_user("patrick")
    assert user is not None

    # Scoping ist optional → „Weiter" bleibt ohne Eingabe aktiv (kein Gate)
    assert wizard._btn_next.isEnabled() is True

    wizard._on_next()  # → W1ProfilePage, optional)
    assert wizard._stack.currentIndex() == 3
    # W1 ist optional → „Weiter" bleibt ohne Eingabe aktiv (kein Gate)
    assert wizard._btn_next.isEnabled() is True

    wizard._on_next()  # → RecoveryCodeDisplay
    assert wizard._stack.currentIndex() == 4

    # RecoveryCode-Seite: Checkbox bestätigen
    assert wizard._btn_next.isEnabled() is False
    wizard._recovery_code._confirm_checkbox.setChecked(True)
    assert wizard._btn_next.isEnabled() is True

    wizard._on_next()  # → Completion
    assert wizard._stack.currentIndex() == 5

    # Recovery-Hash wurde persistiert
    user = UserStore().get_user("patrick")
    assert user is not None
    assert user.recovery_code_hash.startswith("$2")

    # „Weiter" auf Completion schließt den Wizard
    wizard._on_next()
    result = wizard.result_info()
    assert result.completed is True
    assert result.username == "patrick"


def test_wizard_back_button(
    qapp,  # noqa: ARG001
    isolated_home: Path,  # noqa: ARG001
) -> None:
    wizard = FirstRunWizard(app_name="FINLAI")
    wizard._on_next()  # → AdminSetup
    assert wizard._btn_back.isEnabled() is True
    wizard._on_back()
    assert wizard._stack.currentIndex() == 0


def test_wizard_cancel_sets_result_false(
    qapp,  # noqa: ARG001
    isolated_home: Path,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # QMessageBox.question soll automatisch „Yes" antworten.
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(
        QMessageBox,
        "question",
        staticmethod(lambda *args, **kwargs: QMessageBox.StandardButton.Yes),
    )

    wizard = FirstRunWizard(app_name="FINLAI")
    wizard._on_cancel()
    assert wizard.result_info().completed is False
