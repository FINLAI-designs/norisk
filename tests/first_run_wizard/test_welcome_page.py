"""Tests für:class:`WelcomePage`."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from core.first_run_wizard.pages.welcome_page import WelcomePage  # noqa: E402

pytestmark = pytest.mark.gui


def test_welcome_page_contains_app_name(qapp) -> None:  # noqa: ARG001
    page = WelcomePage(app_name="NoRisk by FINLAI")
    visible_texts = _collect_label_texts(page)
    assert any("NoRisk by FINLAI" in t for t in visible_texts)


def test_welcome_page_is_always_complete(qapp) -> None:  # noqa: ARG001
    page = WelcomePage(app_name="FINLAI")
    assert page.is_complete() is True


def _collect_label_texts(widget) -> list[str]:
    from PySide6.QtWidgets import QLabel

    return [lbl.text() for lbl in widget.findChildren(QLabel)]
