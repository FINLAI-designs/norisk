"""GUI-Tests fuer TwoRowTabBar.

Prueft das Zwei-Reihen-Tab-Modell offscreen via pytest-qt:

* Beide Reihen tragen ihre eigenen Tabs (``add_tab(..., row=...)``).
* Exklusive Selektion ueber beide Reihen hinweg (``QButtonGroup``).
* Lazy-Loading via ``set_tab_widget`` ohne Index-Drift.
* Globaler ``currentChanged``-Signal feuert mit dem globalen Index.
"""

from __future__ import annotations

import pytest
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QLabel, QWidget

from tools.einstellungen.gui.two_row_tab_bar import (
    ROW_BOTTOM,
    ROW_TOP,
    TwoRowTabBar,
)


def _make_widget(text: str) -> QWidget:
    """Ein billiges Stub-Widget fuer den Stack."""
    w = QLabel(text)
    w.setObjectName(text)
    return w


def test_add_tab_verteilt_auf_reihen(qtbot):
    """Tabs landen in der angegebenen Reihe und bekommen stabile Indizes."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    icon = QIcon()

    idx0 = bar.add_tab(_make_widget("A"), icon, "A", row=ROW_TOP)
    idx1 = bar.add_tab(_make_widget("B"), icon, "B", row=ROW_BOTTOM)
    idx2 = bar.add_tab(_make_widget("C"), icon, "C", row=ROW_TOP)
    idx3 = bar.add_tab(_make_widget("D"), icon, "D", row=ROW_BOTTOM)

    assert (idx0, idx1, idx2, idx3) == (0, 1, 2, 3)
    assert bar.tab_count() == 4
    assert bar.row_of(idx0) == ROW_TOP
    assert bar.row_of(idx1) == ROW_BOTTOM
    assert bar.row_of(idx2) == ROW_TOP
    assert bar.row_of(idx3) == ROW_BOTTOM
    assert bar.button(idx0).text() == "A"
    assert bar.button(idx3).text() == "D"


def test_erster_tab_wird_automatisch_aktiv(qtbot):
    """Direkt nach dem ersten ``add_tab`` ist Tab 0 aktiv."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)

    assert bar.current_index() == 0
    assert bar.button(0).isChecked()


def test_zweiter_tab_aendert_selektion_nicht(qtbot):
    """Weitere ``add_tab``-Aufrufe halten den ersten Tab aktiv."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)
    bar.add_tab(_make_widget("B"), QIcon(), "B", row=ROW_BOTTOM)
    bar.add_tab(_make_widget("C"), QIcon(), "C", row=ROW_TOP)

    assert bar.current_index() == 0
    assert bar.button(0).isChecked()
    assert not bar.button(1).isChecked()
    assert not bar.button(2).isChecked()


def test_klick_in_unterer_reihe_deselektiert_obere(qtbot):
    """Klick auf einen Tab in Reihe 2 entfernt das Haekchen aus Reihe 1."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("Top1"), QIcon(), "Top1", row=ROW_TOP)
    bar.add_tab(_make_widget("Top2"), QIcon(), "Top2", row=ROW_TOP)
    bar.add_tab(_make_widget("Bot1"), QIcon(), "Bot1", row=ROW_BOTTOM)

    bar.button(2).click()

    assert bar.current_index() == 2
    assert not bar.button(0).isChecked()
    assert not bar.button(1).isChecked()
    assert bar.button(2).isChecked()


def test_klick_zurueck_auf_obere_reihe_deselektiert_untere(qtbot):
    """Wechsel zurueck auf Reihe 1 entfernt das Haekchen aus Reihe 2."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("Top1"), QIcon(), "Top1", row=ROW_TOP)
    bar.add_tab(_make_widget("Bot1"), QIcon(), "Bot1", row=ROW_BOTTOM)
    bar.button(1).click()
    assert not bar.button(0).isChecked()

    bar.button(0).click()

    assert bar.current_index() == 0
    assert bar.button(0).isChecked()
    assert not bar.button(1).isChecked()


def test_current_changed_signal_emittiert_globalen_index(qtbot):
    """``currentChanged`` traegt den globalen Index."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)
    bar.add_tab(_make_widget("B"), QIcon(), "B", row=ROW_BOTTOM)
    bar.add_tab(_make_widget("C"), QIcon(), "C", row=ROW_TOP)

    received: list[int] = []
    bar.currentChanged.connect(received.append)

    bar.button(1).click()
    bar.button(2).click()

    assert received == [1, 2]


def test_set_current_index_aktiviert_richtige_reihe(qtbot):
    """``set_current_index`` aendert die Selektion programmatisch."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)
    bar.add_tab(_make_widget("B"), QIcon(), "B", row=ROW_BOTTOM)

    received: list[int] = []
    bar.currentChanged.connect(received.append)

    bar.set_current_index(1)

    assert bar.current_index() == 1
    assert not bar.button(0).isChecked()
    assert bar.button(1).isChecked()
    assert received == [1]


def test_set_tab_widget_ersetzt_inhalt_und_haelt_index(qtbot):
    """Lazy-Pfad: ``set_tab_widget`` ersetzt das Stub, Index bleibt stabil."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    stub = _make_widget("stub")
    idx = bar.add_tab(stub, QIcon(), "Stub", row=ROW_BOTTOM)
    assert bar.stack().widget(idx) is stub

    real = _make_widget("real")
    bar.set_tab_widget(idx, real, QIcon(), "Real")

    assert bar.button(idx).text() == "Real"
    assert bar.tab_count() == 1
    assert bar.stack().widget(idx) is real


def test_set_tab_widget_zeigt_neues_widget_wenn_tab_aktiv(qtbot):
    """Ist der ersetzte Tab gerade aktiv, wird das neue Widget sichtbar."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("Top"), QIcon(), "Top", row=ROW_TOP)
    stub_idx = bar.add_tab(_make_widget("stub"), QIcon(), "Stub", row=ROW_BOTTOM)
    bar.set_current_index(stub_idx)

    real = _make_widget("real")
    bar.set_tab_widget(stub_idx, real, QIcon(), "Real")

    assert bar.stack().currentWidget() is real


def test_add_tab_lehnt_ungueltige_reihe_ab(qtbot):
    """Eine andere Reihen-Kennung als ``0/1`` ist ein Programmierfehler."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)

    with pytest.raises(ValueError, match="Ungueltige Reihe"):
        bar.add_tab(_make_widget("X"), QIcon(), "X", row=99)


def test_re_klick_auf_aktiven_tab_emittiert_keinen_signal(qtbot):
    """Idempotenz: erneuter Klick auf den aktiven Tab feuert nicht erneut."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)
    bar.add_tab(_make_widget("B"), QIcon(), "B", row=ROW_BOTTOM)
    bar.set_current_index(1)

    received: list[int] = []
    bar.currentChanged.connect(received.append)
    bar.button(1).click()  # bereits aktiv

    assert received == []


def test_stylesheet_wird_auf_alle_buttons_angewandt(qtbot):
    """``set_tab_bar_style_sheet`` propagiert auf bestehende und neue Buttons."""
    bar = TwoRowTabBar()
    qtbot.addWidget(bar)
    bar.add_tab(_make_widget("A"), QIcon(), "A", row=ROW_TOP)

    qss = "QPushButton { background: #abc; }"
    bar.set_tab_bar_style_sheet(qss)

    assert bar.button(0).styleSheet() == qss

    # Spaeter hinzugefuegte Buttons sollen den gleichen Style erben.
    bar.add_tab(_make_widget("B"), QIcon(), "B", row=ROW_BOTTOM)
    assert bar.button(1).styleSheet() == qss
