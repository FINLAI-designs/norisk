"""GUI-Tests fuer HeaderWidget (Startseiten-Begruessung).

Bug P2: der Header griff vorher auf ``Session.username`` zu —
dieses Attribut existiert nicht; der Fallback war hartkodiert ``"Patrick"``.
Korrekt ist ``Session.current_user.first_name`` (oder ``full_name`` /
``username`` als Fallback).
"""

from __future__ import annotations

import pytest

from core.auth.models import User
from core.auth.session import Session
from tools.mainpage.gui.header_widget import HeaderWidget


@pytest.fixture
def _clear_session():
    """Stellt sicher, dass die Session vor + nach jedem Test leer ist."""
    Session().logout()
    yield
    Session().logout()


def _make_user(
    *,
    username: str = "smoketest",
    full_name: str = "Smoke-Test Bot",
    first_name: str = "",
) -> User:
    return User(
        username=username,
        password_hash="dummy",
        role="admin",
        full_name=full_name,
        first_name=first_name,
    )


def test_greeting_zeigt_first_name_wenn_vorhanden(qtbot, _clear_session):
    """``first_name`` hat Vorrang vor ``full_name`` und ``username``."""
    Session().login(_make_user(username="patrick", full_name="Patrick Riederich", first_name="Patrick"))
    widget = HeaderWidget()
    qtbot.addWidget(widget)
    assert ", Patrick!" in widget._lbl_greeting.text()


def test_greeting_faellt_auf_full_name_zurueck(qtbot, _clear_session):
    """Ohne ``first_name`` wird ``full_name`` verwendet."""
    Session().login(_make_user(full_name="Smoke-Test Bot", first_name=""))
    widget = HeaderWidget()
    qtbot.addWidget(widget)
    assert ", Smoke-Test Bot!" in widget._lbl_greeting.text()


def test_greeting_faellt_auf_username_zurueck(qtbot, _clear_session):
    """Ohne ``first_name`` und ohne ``full_name`` wird ``username`` verwendet."""
    Session().login(_make_user(username="someuser", full_name="", first_name=""))
    widget = HeaderWidget()
    qtbot.addWidget(widget)
    assert ", someuser!" in widget._lbl_greeting.text()


def test_greeting_ohne_session_zeigt_keine_anrede(qtbot, _clear_session):
    """Ohne eingeloggten Benutzer wird kein Name angehaengt."""
    widget = HeaderWidget()
    qtbot.addWidget(widget)
    text = widget._lbl_greeting.text()
    # Erwartet "Guten Morgen!" / "Guten Tag!" /... — kein Komma + Name.
    assert "," not in text
    assert text.endswith("!")


def test_greeting_kein_hardcoded_patrick_fallback(qtbot, _clear_session):
    """Bug P2-Regression: kein hartcodiertes 'Patrick' wenn ein anderer User aktiv ist."""
    Session().login(_make_user(username="alice", full_name="Alice Anderson", first_name="Alice"))
    widget = HeaderWidget()
    qtbot.addWidget(widget)
    text = widget._lbl_greeting.text()
    assert "Patrick" not in text
    assert ", Alice!" in text
