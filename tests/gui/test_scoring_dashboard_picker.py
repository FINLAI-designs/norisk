"""GUI-Tests für Step 8: Subjekt-Picker + Kunden-Modus im Scoring-Dashboard.

Offscreen (pytest-qt). Prüft die Modus-Umschaltung (SELF <-> Kunde) und den
Erfassungs-Flow, NICHT die visuelle Darstellung.
"""

from __future__ import annotations

import pytest

from core.herkunft import Herkunft
from core.security_subject.models import SubjectKind
from tools.security_scoring.application.scoring_service import ScoringService
from tools.security_scoring.gui.scoring_dashboard_widget import ScoringDashboardWidget


class _Subj:
    """Duck-typed core Subject (Widget nutzt nur kind/subject_id/name)."""

    def __init__(self, kind: SubjectKind, sid: str, name: str) -> None:
        self.kind = kind
        self.subject_id = sid
        self.name = name


class _Store:
    def __init__(self, subjects: list[_Subj]) -> None:
        self._subjects = subjects

    def list_all(self) -> list[_Subj]:
        return list(self._subjects)

    def get(self, subject_id: str):  # noqa: ANN201
        return next((s for s in self._subjects if s.subject_id == subject_id), None)

    def ensure_self_subject(self, name: str):  # noqa: ANN201, ARG002
        return next((s for s in self._subjects if s.kind == SubjectKind.EIGENES), None)


@pytest.fixture
def _store() -> _Store:
    return _Store(
        [
            _Subj(SubjectKind.EIGENES, "self", "Mein PC"),
            _Subj(SubjectKind.KUNDE, "cust-1", "Müller GmbH"),
        ]
    )


def _widget(store: _Store) -> ScoringDashboardWidget:
    service = ScoringService(subject_store=store)
    return ScoringDashboardWidget(service=service, subject_store=store)


def test_picker_hat_eigenes_und_kunde(app, _store) -> None:  # noqa: ANN001
    w = _widget(_store)
    assert w._cmb_subject is not None
    assert w._cmb_subject.count() == 2


def test_modus_umschaltung(app, _store) -> None:  # noqa: ANN001
    w = _widget(_store)
    # Default (eigenes / index 0): Erfassen aus, Neu berechnen an.
    assert w._btn_erfassen.isHidden() is True
    assert w._btn_calc.isEnabled() is True
    # -> Kunde: Erfassen an, Neu berechnen aus.
    w._cmb_subject.setCurrentIndex(1)
    assert w._btn_erfassen.isHidden() is False
    assert w._btn_calc.isEnabled() is False
    # -> zurück zu eigenes: wieder Messung.
    w._cmb_subject.setCurrentIndex(0)
    assert w._btn_erfassen.isHidden() is True
    assert w._btn_calc.isEnabled() is True


def test_kunde_live_scan_geblockt(app, _store) -> None:  # noqa: ANN001
    w = _widget(_store)
    w._cmb_subject.setCurrentIndex(1)  # Kunde
    # _on_berechnen darf im Kunden-Modus keinen Thread starten (Backstop).
    w._on_berechnen()
    assert w._thread is None


def test_erfassen_persistiert_erfasst(app, _store, monkeypatch) -> None:  # noqa: ANN001
    from PySide6.QtWidgets import QDialog

    class _FakeDialog:
        def __init__(self, *a, **k) -> None:  # noqa: ANN002, ANN003
            pass

        def exec(self) -> int:
            return QDialog.DialogCode.Accepted

        def get_facts(self) -> dict[str, bool | None]:
            return {"firewall": True, "backup": True}

    monkeypatch.setattr(
        "tools.security_scoring.gui.dialogs.kunden_hardening_dialog.KundenHardeningDialog",
        _FakeDialog,
    )
    w = _widget(_store)
    w._cmb_subject.setCurrentIndex(1)  # Kunde -> _current_subject = cust-1
    w._on_erfassen()
    geladen = w._service.lade_letztes_hardening_result_by_subject("cust-1")
    assert geladen is not None
    assert geladen.herkunft is Herkunft.ERFASST
