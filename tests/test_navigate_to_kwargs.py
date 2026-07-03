"""Tests für ``NavigationMixin.navigate_to(key, **kwargs)`` (Sprint S3d).

Pure-Python-Tests gegen die unbound Method — wir bauen einen
``_StubMain`` mit den vom Mixin erwarteten Attributen
(``_docks``, ``_welcome_dock``, ``tool_activated``,
``_get_active_widget_for``) und prüfen die Routing-Pfade.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock

from core.navigation_mixin import NavigationMixin


class _StubMain:
    """Minimaler MainWindow-Stub mit allen vom Mixin erwarteten Feldern."""

    def __init__(self, widget=None):  # noqa: ANN001
        self._docks: dict = {}
        self._welcome_dock = MagicMock()
        self.tool_activated = MagicMock()
        self._navigated: list[str] = []
        self._widget = widget

    # NavigationMixin braucht diese Methoden:
    def _on_sidebar_navigate(self, key: str) -> None:
        self._navigated.append(key)

    def _get_active_widget_for(self, key: str) -> object:  # noqa: ARG002
        return self._widget


# ---------------------------------------------------------------------------
# Backwards-Compat
# ---------------------------------------------------------------------------


def test_navigate_to_ohne_kwargs_aktiviert_dock_ohne_apply():
    """``navigate_to(key)`` ohne kwargs verhält sich wie vor S3d."""
    widget = MagicMock()
    stub = _StubMain(widget=widget)
    NavigationMixin.navigate_to(stub, "password_checker")  # type: ignore[arg-type]
    assert stub._navigated == ["password_checker"]
    widget.apply_navigation.assert_not_called()


def test_navigate_to_ohne_widget_keine_exception():
    """Wenn ``_get_active_widget_for`` ``None`` liefert, kein Crash."""
    stub = _StubMain(widget=None)
    NavigationMixin.navigate_to(  # type: ignore[arg-type]
        stub, "password_checker", url="https://example.com"
    )
    assert stub._navigated == ["password_checker"]


def test_navigate_to_widget_ohne_apply_navigation_kwargs_ignoriert():
    """Widget ohne ``apply_navigation`` → kwargs werden geschluckt."""

    class _NoApply:
        pass

    stub = _StubMain(widget=_NoApply())
    NavigationMixin.navigate_to(  # type: ignore[arg-type]
        stub, "password_checker", url="https://example.com"
    )
    # Kein Crash, keine Side-Effects auf _navigated darüber hinaus.
    assert stub._navigated == ["password_checker"]


# ---------------------------------------------------------------------------
# apply_navigation-Pfad
# ---------------------------------------------------------------------------


def test_navigate_to_kwargs_werden_an_apply_navigation_durchgereicht():
    """Widget mit ``apply_navigation`` bekommt die kwargs."""
    widget = MagicMock()
    stub = _StubMain(widget=widget)
    NavigationMixin.navigate_to(  # type: ignore[arg-type]
        stub, "api_security", url="https://api.example.com"
    )
    widget.apply_navigation.assert_called_once_with(url="https://api.example.com")


def test_navigate_to_apply_navigation_exception_wird_geschluckt():
    """``apply_navigation``-Exception darf den Caller nicht crashen."""
    widget = MagicMock()
    widget.apply_navigation.side_effect = RuntimeError("kaputt")
    stub = _StubMain(widget=widget)
    # Darf nicht raisen — _navigated zeigt: Tab wurde trotzdem geöffnet.
    NavigationMixin.navigate_to(  # type: ignore[arg-type]
        stub, "api_security", url="https://x.de"
    )
    assert stub._navigated == ["api_security"]


def test_navigate_to_mehrere_kwargs():
    """Mehrere kwargs werden 1:1 weitergegeben (forward-kompatibel)."""
    widget = MagicMock()
    stub = _StubMain(widget=widget)
    NavigationMixin.navigate_to(  # type: ignore[arg-type]
        stub, "tool_xy", domain="example.com", port=443, foo="bar"
    )
    widget.apply_navigation.assert_called_once_with(
        domain="example.com", port=443, foo="bar"
    )
