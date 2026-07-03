"""Tests für:class:`AdminSetupPage` — Validierung und Persistenz."""

from __future__ import annotations

from pathlib import Path

import bcrypt
import pytest

pytest.importorskip("PySide6")

from core.auth.user_store import UserStore  # noqa: E402
from core.exceptions import ValidationError  # noqa: E402
from core.first_run_wizard.pages.admin_setup_page import (  # noqa: E402
    AdminSetupPage,
    email_typo_hint,
    suggest_username,
    validate_email,
    validate_first_name,
    validate_password,
    validate_username,
)

pytestmark = pytest.mark.gui


def _fill_valid(page: AdminSetupPage) -> None:
    """Füllt das Formular mit gültigen Werten (Helper für mehrere Tests)."""
    page._first_name.setText("Patrick")
    page._username.setText("patrick")
    page._email.setText("patrick@example.com")
    page._full_name.setText("Patrick Riederich")
    page._password.setText("geheim12")
    page._password_repeat.setText("geheim12")


@pytest.fixture
def isolated_user_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> UserStore:
    """Leitet ``~/.finlai/users.json`` auf tmp_path um."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    # Modul-Konstanten neu binden, da sie zur Import-Zeit eingefroren werden.
    finlai_dir = fake_home / ".finlai"
    users_file = finlai_dir / "users.json"
    monkeypatch.setattr("core.auth.user_store._FINLAI_DIR", finlai_dir)
    monkeypatch.setattr("core.auth.user_store._USERS_FILE", users_file)
    return UserStore()


# ---------------------------------------------------------------------------
# Reine Validierungsfunktionen — keine Qt-Fixture nötig
# ---------------------------------------------------------------------------


class TestValidateUsername:
    def test_empty_is_rejected(self) -> None:
        assert validate_username("") is not None

    def test_too_short_is_rejected(self) -> None:
        assert validate_username("ab") is not None

    def test_whitespace_is_rejected(self) -> None:
        assert validate_username("foo bar") is not None

    def test_reserved_admin_is_rejected(self) -> None:
        assert validate_username("admin") is not None
        assert validate_username("ADMIN") is not None
        assert validate_username("Root") is not None

    def test_valid_username_ok(self) -> None:
        assert validate_username("patrick") is None


class TestValidatePassword:
    def test_too_short_is_rejected(self) -> None:
        assert validate_password("abc12") is not None

    def test_missing_letter_is_rejected(self) -> None:
        assert validate_password("12345678") is not None

    def test_missing_digit_is_rejected(self) -> None:
        assert validate_password("abcdefgh") is not None

    def test_valid_password_ok(self) -> None:
        assert validate_password("geheim12") is None


# ---------------------------------------------------------------------------
# Widget-Tests (QApplication über pytest-qt-Fixture ``qapp``)
# ---------------------------------------------------------------------------


def test_page_is_not_complete_when_empty(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    assert page.is_complete() is False


def test_page_completes_with_valid_input(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    _fill_valid(page)
    assert page.is_complete() is True


def test_password_mismatch_blocks_completion(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    _fill_valid(page)
    page._password_repeat.setText("anders12")
    assert page.is_complete() is False


def test_commit_creates_user(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    _fill_valid(page)

    page.commit()

    user = isolated_user_store.get_user("patrick")
    assert user is not None
    assert user.role == "admin"
    assert user.full_name == "Patrick Riederich"
    assert user.first_name == "Patrick"
    assert user.email == "patrick@example.com"
    assert bcrypt.checkpw(b"geheim12", user.password_hash.encode("utf-8"))
    assert page.created_username == "patrick"
    assert page.created_first_name == "Patrick"


def test_commit_removes_placeholder_admin(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    # UserStore.__init__ hat bereits einen Placeholder-Admin angelegt.
    assert isolated_user_store.get_user("admin") is not None

    page = AdminSetupPage(user_store=isolated_user_store)
    _fill_valid(page)
    page.commit()

    assert isolated_user_store.get_user("admin") is None


def test_commit_keeps_real_admin(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    # Szenario: jemand hat „admin" manuell mit Passwort angelegt.
    isolated_user_store.set_password_admin("admin", "adminPW12")

    page = AdminSetupPage(user_store=isolated_user_store)
    _fill_valid(page)
    page.commit()

    # Der echte Admin darf NICHT gelöscht werden.
    assert isolated_user_store.get_user("admin") is not None


def test_commit_raises_on_invalid_input(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    """commit bei leerem Formular wirft ``ValidationError``.

    Migration 2026-04 (typed exceptions): ``AdminSetupPage.commit``
    wirft jetzt ``ValidationError`` (Subklasse von ``ValueError``),
    nicht mehr generisches ``RuntimeError``. Der Test wurde vorher
    uebersehen — entdeckt im Smoke 2026-05-14.
    """
    page = AdminSetupPage(user_store=isolated_user_store)
    with pytest.raises(ValidationError):
        page.commit()


# ---------------------------------------------------------------------------
# T3: Vorname, E-Mail und Autosuggest
# ---------------------------------------------------------------------------


class TestValidateFirstName:
    def test_empty_is_rejected(self) -> None:
        assert validate_first_name("") is not None

    def test_too_short_is_rejected(self) -> None:
        assert validate_first_name("A") is not None

    def test_umlauts_ok(self) -> None:
        assert validate_first_name("Jürgen") is None
        assert validate_first_name("Änne-Marie") is None

    def test_digits_are_rejected(self) -> None:
        assert validate_first_name("Max2") is not None

    def test_special_chars_are_rejected(self) -> None:
        assert validate_first_name("Max!") is not None


class TestValidateEmail:
    def test_empty_is_rejected(self) -> None:
        assert validate_email("") is not None

    def test_missing_at_is_rejected(self) -> None:
        assert validate_email("patrick.gmail.com") is not None

    def test_missing_tld_is_rejected(self) -> None:
        assert validate_email("foo@bar") is not None

    def test_valid_email_ok(self) -> None:
        assert validate_email("patrick@example.com") is None


class TestEmailTypoHint:
    def test_no_hint_for_correct_email(self) -> None:
        assert email_typo_hint("patrick@gmail.com") is None

    def test_hint_for_gmial(self) -> None:
        hint = email_typo_hint("patrick@gmial.com")
        assert hint is not None
        assert "gmail.com" in hint

    def test_hint_for_yaho(self) -> None:
        hint = email_typo_hint("a@yaho.com")
        assert hint is not None
        assert "yahoo.com" in hint

    def test_hint_for_hotnail(self) -> None:
        hint = email_typo_hint("b@hotnail.com")
        assert hint is not None
        assert "hotmail.com" in hint


class TestSuggestUsername:
    def test_basic_lowercase(self) -> None:
        assert suggest_username("Patrick") == "patrick"

    def test_umlauts_transliterated(self) -> None:
        assert suggest_username("Jürgen") == "juergen"
        assert suggest_username("Björn") == "bjoern"
        assert suggest_username("Änne") == "aenne"

    def test_eszett(self) -> None:
        assert suggest_username("Weiß") == "weiss"

    def test_whitespace_and_hyphens_stripped(self) -> None:
        assert suggest_username("Anne-Marie") == "annemarie"
        assert suggest_username("Hans Peter") == "hanspeter"
        assert suggest_username("O'Connor") == "oconnor"


def test_autosuggest_populates_username(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    page._first_name.setText("Jürgen")
    assert page._username.text() == "juergen"


def test_manual_edit_stops_autosuggest(
    qapp,  # noqa: ARG001
    isolated_user_store: UserStore,
) -> None:
    page = AdminSetupPage(user_store=isolated_user_store)
    page._first_name.setText("Max")
    # Simuliere manuelle Bearbeitung
    page._username.setText("custom")
    page._on_username_edited("custom")
    # Weitere Vornamens-Eingabe darf den Username nicht mehr überschreiben
    page._first_name.setText("Moritz")
    assert page._username.text() == "custom"
