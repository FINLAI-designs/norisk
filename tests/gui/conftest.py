"""
conftest — Fixtures für pytest-qt GUI-Tests.

Stellt QApplication und Theme-Fixtures für alle GUI-Tests bereit.
"""

import pytest

from core import theme
from core.auth import login_attempts as _login_attempts


@pytest.fixture(autouse=True)
def _isolate_login_attempts(tmp_path, monkeypatch):
    """Leitet den persistenten Login-Lockout pro Test auf ``tmp_path`` um.

    GUI-Tests, die ``LoginWindow._on_login`` auslösen (z. B.
    ``test_login_window``), schreiben sonst echte Fehlversuche nach
    ``~/.finlai/login_attempts.json`` und sperren das geteilte Test-Konto
    dauerhaft — nachfolgende Tests scheitern dann an „Konto vorübergehend
    gesperrt" statt am erwarteten Verhalten. Die Umleitung isoliert jeden
    Test und lässt die echte Lockout-Datei unangetastet.
    """
    monkeypatch.setattr(_login_attempts, "_FINLAI_DIR", tmp_path)
    monkeypatch.setattr(
        _login_attempts, "_ATTEMPTS_FILE", tmp_path / "login_attempts.json"
    )


@pytest.fixture(scope="session")
def app(qapp):
    """QApplication Fixture.

    pytest-qt stellt qapp bereit.
    Wir initialisieren zusätzlich das FINLAI Theme.
    """
    theme.set_dark()
    theme.apply(qapp)
    return qapp


@pytest.fixture
def dark_theme():
    """Setzt Dark Theme für Test."""
    theme.set_dark()
    yield
    theme.set_dark()  # Reset


@pytest.fixture
def light_theme():
    """Setzt Light Theme für Test."""
    theme.set_light()
    yield
    theme.set_dark()  # Reset nach Test
