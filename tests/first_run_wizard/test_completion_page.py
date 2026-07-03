"""Tests für:class:`CompletionPage`."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from core.first_run_wizard.pages.completion_page import CompletionPage  # noqa: E402

pytestmark = pytest.mark.gui


def test_completion_page_is_complete(qapp) -> None:  # noqa: ARG001
    page = CompletionPage()
    assert page.is_complete() is True


def test_set_username_updates_label(qapp) -> None:  # noqa: ARG001
    from PySide6.QtWidgets import QLabel

    page = CompletionPage()
    page.set_username("patrick")
    labels = [lbl.text() for lbl in page.findChildren(QLabel)]
    assert any("patrick" in t for t in labels)
    assert page.username == "patrick"


def test_username_none_by_default(qapp) -> None:  # noqa: ARG001
    page = CompletionPage()
    assert page.username is None
