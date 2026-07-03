"""Tests für:class:`core.widgets.welcome_toast.WelcomeToast`."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from core.widgets.welcome_toast import WelcomeToast  # noqa: E402

pytestmark = pytest.mark.gui


def _label_text(toast: WelcomeToast) -> str:
    from PySide6.QtWidgets import QLabel

    return next(lbl.text() for lbl in toast.findChildren(QLabel))


def test_first_login_message(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="Patrick", first_login=True, app_display_name="NoRisk"
    )
    text = _label_text(toast)
    assert "Willkommen bei NoRisk" in text
    assert "Patrick" in text
    assert "Dein Konto ist eingerichtet" in text
    toast.deleteLater()


def test_regular_login_message(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="Patrick", first_login=False, app_display_name="NoRisk"
    )
    text = _label_text(toast)
    assert "Willkommen zurück" in text
    assert "Patrick" in text
    toast.deleteLater()


def test_dimensions(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="X", first_login=False, app_display_name="FINLAI"
    )
    assert toast.width() == WelcomeToast.WIDTH
    assert toast.height() == WelcomeToast.HEIGHT
    toast.deleteLater()


def test_display_name_norisk(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="Patrick", first_login=True, app_display_name="NoRisk"
    )
    text = _label_text(toast)
    assert "NoRisk" in text
    assert "FINLAI" not in text
    toast.deleteLater()


def test_display_name_finlai(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="Patrick", first_login=True, app_display_name="FINLAI"
    )
    text = _label_text(toast)
    assert "FINLAI" in text
    toast.deleteLater()


def test_display_name_automate(qapp) -> None:  # noqa: ARG001
    toast = WelcomeToast(
        first_name="Patrick", first_login=True, app_display_name="AUTOMATE"
    )
    text = _label_text(toast)
    assert "AUTOMATE" in text
    toast.deleteLater()


def test_empty_first_name_does_not_render(qapp) -> None:  # noqa: ARG001
    """Leerer Vorname →:meth:`show_toast` zeigt nichts, kein Crash."""
    toast = WelcomeToast(
        first_name="   ", first_login=False, app_display_name="FINLAI"
    )
    toast.show_toast("patrick")
    # Kein show wurde ausgeführt — Widget bleibt unsichtbar.
    assert toast.isVisible() is False


def test_none_first_name_does_not_render(qapp) -> None:  # noqa: ARG001
    """``None`` Vorname →:meth:`show_toast` zeigt nichts."""
    toast = WelcomeToast(
        first_name=None, first_login=False, app_display_name="FINLAI"
    )
    toast.show_toast("patrick")
    assert toast.isVisible() is False


def test_empty_first_name_no_audit(qapp, monkeypatch) -> None:  # noqa: ARG001
    """Leerer Vorname → kein Audit-Event ``WELCOME_TOAST_SHOWN``."""
    calls: list[tuple[str, dict]] = []

    def _fake_log(action: str, data: dict) -> None:
        calls.append((action, data))

    from core.audit_log import AuditLogger

    monkeypatch.setattr(AuditLogger, "log_action", lambda self, a, d: _fake_log(a, d))

    toast = WelcomeToast(
        first_name="", first_login=True, app_display_name="NoRisk"
    )
    toast.show_toast("patrick")
    assert not any(action == "WELCOME_TOAST_SHOWN" for action, _ in calls)
