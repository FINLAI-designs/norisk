"""GUI-Tests für den Passwort-Checker — Breach-aware Stärke-Anzeige-F2).

Lockt ein, dass ein HIBP-Treffer den (zunächst score-basiert gerenderten)
Stärke-Balken hart auf SEHR_SCHWACH/0/„KOMPROMITTIERT" überschreibt, während ein
Negativ-Ergebnis die score-basierte Anzeige unangetastet lässt.

Headless via pytest-qt (offscreen); der HIBP-Slot wird direkt aufgerufen, kein
Netzwerk.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.password_checker.application.password_service import PasswordService
from tools.password_checker.domain.models import PasswordStaerke
from tools.password_checker.gui.password_checker_widget import PasswordCheckerWidget

pytestmark = pytest.mark.gui


@pytest.fixture
def widget(qtbot, app):  # noqa: ARG001
    """Passwort-Checker-Widget mit gemocktem Service (kein Netzwerk)."""
    service = MagicMock(spec=PasswordService)
    w = PasswordCheckerWidget(service)
    qtbot.add_widget(w)
    return w


def test_hibp_treffer_kappt_staerke_balken(widget):
    """Ein Breach-Treffer überschreibt die grüne Voranzeige auf KOMPROMITTIERT."""
    # Synchrone Voranzeige: starkes Passwort (grün, hoher Score).
    widget._render_staerke(PasswordStaerke.SEHR_STARK, 95)  # noqa: SLF001
    assert widget._progress_staerke.value() == 95  # noqa: SLF001

    # HIBP-Treffer trifft asynchron ein.
    widget._on_hibp_fertig(True, 999)  # noqa: SLF001

    assert widget._progress_staerke.value() == 0  # noqa: SLF001
    assert "KOMPROMITTIERT" in widget._lbl_score.text()  # noqa: SLF001
    assert "Datenpannen" in widget._lbl_breach.text()  # noqa: SLF001


def test_hibp_kein_treffer_laesst_staerke(widget):
    """Ohne Treffer bleibt die score-basierte Stärke-Anzeige unverändert."""
    widget._render_staerke(PasswordStaerke.SEHR_STARK, 95)  # noqa: SLF001
    widget._on_hibp_fertig(False, 0)  # noqa: SLF001

    assert widget._progress_staerke.value() == 95  # noqa: SLF001
    assert "KOMPROMITTIERT" not in widget._lbl_score.text()  # noqa: SLF001


def test_stale_worker_ergebnis_wird_verworfen(widget):
    """Ein Ergebnis von einem abgelösten Worker darf die Anzeige des aktuell
    geprüften Passworts NICHT überschreiben-F2 Race-Guard via sender)."""
    widget._render_staerke(PasswordStaerke.SEHR_STARK, 95)  # noqa: SLF001
    # Aktueller Worker ist ein anderes Objekt als der (None-)Direktaufruf-Sender:
    widget._worker = object()  # noqa: SLF001 — simuliert einen neuen, aktiven Check
    widget._on_hibp_fertig(True, 999)  # noqa: SLF001 — stale (sender None != _worker)

    # Balken NICHT gekappt — das verspätete Alt-Ergebnis wurde verworfen.
    assert widget._progress_staerke.value() == 95  # noqa: SLF001
    assert "KOMPROMITTIERT" not in widget._lbl_score.text()  # noqa: SLF001
