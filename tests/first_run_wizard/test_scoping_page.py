"""Tests für die Einstiegs-Scoping-Seite des First-Run-Wizards.

Deckt den Pflicht-Roundtrip Widget→Adapter→Repo→Load, das optionale
``is_complete`` (kein Gate) und die fail-soft-Persistenz ohne SubjectStore.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("PySide6")

from core.database import encrypted_db as edb  # noqa: E402
from core.first_run_wizard.pages.scoping_page import CompanyScopingPage  # noqa: E402
from tools.security_scoring.application.subject_store import (  # noqa: E402
    create_default_subject_store,
)

pytestmark = pytest.mark.gui


def test_is_complete_is_always_true(qapp) -> None:  # noqa: ARG001
    # Scoping ist optional → nie ein Gate.
    page = CompanyScopingPage()
    assert page.is_complete() is True


def test_commit_roundtrip_persists_on_self_subject(
    qapp,  # noqa: ARG001
    tmp_path: Path,
) -> None:
    with patch.object(edb, "DB_DIR", tmp_path):
        # Selbst-Subjekt existiert (wie nach dem Startup-Backfill).
        store = create_default_subject_store()
        assert store is not None
        store.ensure_self_subject("Mein System")

        page = CompanyScopingPage()
        page._fte.setValue(42)
        page._umsatz.setValue(5_000_000)
        page._bilanz.setValue(3_000_000)
        page._sektor.setCurrentIndex(page._sektor.findData("bankwesen"))
        page._rolle.setCurrentIndex(
            page._rolle.findData("IT-Leitung / IT-Verantwortung")
        )

        page.commit()

        reread = store.get_self()
        assert reread is not None
        assert reread.fte == 42
        assert reread.umsatz_eur == 5_000_000
        assert reread.bilanzsumme_eur == 3_000_000
        assert reread.sektor_key == "bankwesen"
        assert reread.nis2_anhang == "I"  # bankwesen → Anhang I
        assert reread.rolle == "IT-Leitung / IT-Verantwortung"


def test_commit_empty_is_noop(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    with patch.object(edb, "DB_DIR", tmp_path):
        store = create_default_subject_store()
        assert store is not None
        store.ensure_self_subject("Mein System")

        page = CompanyScopingPage()
        page.commit()  # nichts erfasst → kein Schreibvorgang

        reread = store.get_self()
        assert reread is not None
        assert reread.fte is None
        assert reread.sektor_key == ""


def test_commit_failsoft_without_store(
    qapp,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Resolver liefert None (z. B. Nicht-NoRisk-App) → commit darf nicht werfen.
    monkeypatch.setattr(
        "core.first_run_wizard.pages.scoping_page.create_subject_store",
        lambda: None,
    )
    page = CompanyScopingPage()
    page._fte.setValue(5)
    page.commit()  # kein Crash, keine Persistenz
