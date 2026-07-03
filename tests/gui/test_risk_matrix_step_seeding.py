"""test_risk_matrix_step_seeding.

Live-Test: Die Risikomatrix re-derived NICHT, wenn Audit-Antworten geaendert
werden (Phishing auf alle-Ja blieb als Risiko). Ursache: das Seeding aus den
Antworten lief nur EINMAL (und gar nicht im Edit-Modus).

Patrick-Entscheid: bei JEDEM Betreten neu ableiten, ABER manuell angepasste
Eintraege schonen. Deckt ``RiskMatrixStep.seed_from_audit`` ab:
  * erstes Seeding ersetzt den Katalog-Default,
  * erneutes Seeding aktualisiert einen unveraenderten Eintrag,
  * erneutes Seeding LAESST einen manuell geaenderten Eintrag unangetastet.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tools.customer_audit.domain.risk_entities import (
    DEFAULT_RISK_CATALOG_BY_KEY,
    RiskImpact,
    RiskProbability,
)
from tools.customer_audit.gui.step_widgets.risk_matrix_step import RiskMatrixStep

pytestmark = pytest.mark.gui

_KEY = next(iter(DEFAULT_RISK_CATALOG_BY_KEY))  # irgendein Katalog-Risiko
_LOW = (RiskProbability.SELTEN, RiskImpact.VERNACHLAESSIGBAR)
_HIGH = (RiskProbability.SEHR_HAEUFIG, RiskImpact.EXISTENZBEDROHEND)
_MANUAL = (RiskProbability.MITTEL, RiskImpact.BEGRENZT)


def _step(qtbot):
    step = RiskMatrixStep()
    qtbot.addWidget(step)
    return step


def _value(step) -> tuple:
    a = next(
        a
        for a in step._assessments  # noqa: SLF001
        if a.catalog_key == _KEY and not a.is_custom
    )
    return (a.probability, a.impact)


def _set_manual(step, value) -> None:
    for i, a in enumerate(step._assessments):  # noqa: SLF001
        if a.catalog_key == _KEY and not a.is_custom:
            step._assessments[i] = replace(  # noqa: SLF001
                a, probability=value[0], impact=value[1]
            )
            return


@pytest.mark.usefixtures("app")
class TestRiskMatrixSeeding:
    def test_first_seed_replaces_default(self, qtbot) -> None:
        step = _step(qtbot)
        step.seed_from_audit({_KEY: _LOW})
        assert _value(step) == _LOW

    def test_reseed_updates_untouched_entry(self, qtbot) -> None:
        # Unveraendert seit dem letzten Ableiten -> neue Ableitung gewinnt.
        step = _step(qtbot)
        step.seed_from_audit({_KEY: _HIGH})
        assert _value(step) == _HIGH
        step.seed_from_audit({_KEY: _LOW})
        assert _value(step) == _LOW

    def test_reseed_preserves_manual_tweak(self, qtbot) -> None:
        # Manuell angepasst -> beim erneuten Ableiten NICHT ueberschreiben.
        step = _step(qtbot)
        step.seed_from_audit({_KEY: _HIGH})  # Baseline = HIGH
        _set_manual(step, _MANUAL)  # Auditor setzt von Hand
        step.seed_from_audit({_KEY: _LOW})  # neue Ableitung
        assert _value(step) == _MANUAL  # manueller Wert bleibt

    def test_set_assessments_clears_seed_baseline(self, qtbot) -> None:
        # K-1: Eine neue Bewertungs-Liste (zweites Audit via load_for_edit auf
        # DERSELBEN Instanz) muss die alte Seeding-Baseline verwerfen. Sonst gilt
        # ein im neuen Audit manuell gesetzter Wert, der zufaellig = alter Baseline
        # ist, als „unveraendert" und wuerde faelschlich neu abgeleitet.
        step = _step(qtbot)
        step.seed_from_audit({_KEY: _HIGH})  # Audit A: Baseline = HIGH
        # Audit B wird geladen: derselbe Key ist manuell HIGH gesetzt (zufaellig
        # gleich der alten Baseline), aber als Eingabe des NEUEN Audits.
        neu = [
            replace(a, probability=_HIGH[0], impact=_HIGH[1])
            if a.catalog_key == _KEY and not a.is_custom
            else a
            for a in step._assessments  # noqa: SLF001
        ]
        step.set_assessments(neu)
        step.seed_from_audit({_KEY: _LOW})  # Audit B leitet LOW ab
        assert _value(step) == _HIGH  # manueller Wert von Audit B bleibt
