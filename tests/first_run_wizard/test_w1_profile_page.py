"""Tests für die W1-Profil-Seite des First-Run-Wizards.

Deckt den Roundtrip Widget→Adapter→Repo→Load, das optionale ``is_complete``
(kein Gate), die Sentinel-Semantik von „keine Angabe" (unverändert) und die
fail-soft-Persistenz ohne SubjectStore.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("PySide6")

from core.database import encrypted_db as edb  # noqa: E402
from core.first_run_wizard.pages.w1_profile_page import W1ProfilePage  # noqa: E402
from tools.security_scoring.application.subject_store import (  # noqa: E402
    create_default_subject_store,
)

pytestmark = pytest.mark.gui


def test_is_complete_is_always_true(qapp) -> None:  # noqa: ARG001
    # W1 ist optional → nie ein Gate.
    page = W1ProfilePage()
    assert page.is_complete() is True


def test_commit_roundtrip_persists_on_self_subject(
    qapp,  # noqa: ARG001
    tmp_path: Path,
) -> None:
    with patch.object(edb, "DB_DIR", tmp_path):
        store = create_default_subject_store()
        assert store is not None
        store.ensure_self_subject("Mein System")

        page = W1ProfilePage()
        page._segment.setCurrentIndex(page._segment.findData("epu"))
        page._api.setCurrentIndex(page._api.findData(1))
        page._website.setCurrentIndex(page._website.findData(0))
        page._entwickler.setCurrentIndex(page._entwickler.findData(1))

        page.commit()

        reread = store.get_self()
        assert reread is not None
        assert reread.segment == "epu"
        assert reread.hat_eigene_api == 1
        assert reread.hat_eigene_website == 0  # „Nein" → 0, nicht None
        assert reread.ist_entwickler == 1
        # „keine Angabe" gelassen → unverändert (Default None)
        assert reread.hat_server_infrastruktur is None


def test_commit_empty_is_noop(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    with patch.object(edb, "DB_DIR", tmp_path):
        store = create_default_subject_store()
        assert store is not None
        store.ensure_self_subject("Mein System")

        page = W1ProfilePage()
        page.commit()  # nichts gewählt → kein Schreibvorgang

        reread = store.get_self()
        assert reread is not None
        assert reread.segment == ""
        assert reread.hat_eigene_api is None


def test_keine_angabe_preserves_existing_value(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    # Sentinel-Semantik: ein zuvor gesetztes Flag bleibt erhalten, wenn die W1-
    # Seite es auf „keine Angabe" lässt (wichtig für spätere Cockpit-Wiederholung).
    with patch.object(edb, "DB_DIR", tmp_path):
        store = create_default_subject_store()
        assert store is not None
        own = store.ensure_self_subject("Mein System")
        store.update_profile_w1(own.subject_id, hat_eigene_api=1)

        page = W1ProfilePage()
        page._segment.setCurrentIndex(page._segment.findData("kmu_klein"))
        # _api bleibt auf „keine Angabe" (Default-Index 0)
        page.commit()

        reread = store.get_self()
        assert reread is not None
        assert reread.segment == "kmu_klein"
        assert reread.hat_eigene_api == 1  # erhalten, nicht auf None überschrieben


def test_commit_failsoft_without_store(
    qapp,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.first_run_wizard.pages.w1_profile_page.create_subject_store",
        lambda: None,
    )
    page = W1ProfilePage()
    page._api.setCurrentIndex(page._api.findData(1))
    page.commit()  # kein Crash, keine Persistenz
