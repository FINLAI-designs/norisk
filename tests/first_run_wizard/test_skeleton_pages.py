"""Smoke-Tests für die Skelett-Seiten des First-Run-Wizards."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")

from core.first_run_wizard.pages import (  # noqa: E402
    BackupLocationPage,
    CompanyInfoPage,
    TwoFactorPage,
)


@pytest.mark.parametrize(
    "page_cls",
    [TwoFactorPage, CompanyInfoPage, BackupLocationPage],
)
def test_skeleton_page_constructs(
    qapp,  # noqa: ARG001
    page_cls: type,
) -> None:
    page = page_cls()
    assert page is not None
    # Skelette haben keine Pflicht-Eingabe → immer „komplett".
    assert page.is_complete() is True
    assert page.TITLE
