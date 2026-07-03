"""Tests für E1: Abweichungs-Erkennung Selbsteinschätzung vs Messung."""

from __future__ import annotations

from tools.norisk_dashboard.domain.score_abweichung import (
    DRASTISCH_SCHWELLE,
    bewerte_score_abweichung,
)


def test_none_eingaben_kein_abgleich() -> None:
    assert bewerte_score_abweichung(None, 80) is None
    assert bewerte_score_abweichung(80, None) is None


def test_nahe_beieinander_nicht_drastisch() -> None:
    a = bewerte_score_abweichung(80, 72)
    assert a is not None
    assert a.drastisch is False
    assert a.differenz == 8.0


def test_audit_ueberschaetzt_drastisch() -> None:
    a = bewerte_score_abweichung(85, 40)
    assert a is not None
    assert a.drastisch is True
    assert a.richtung == "ueberschaetzt"
    assert "ÜBER" in a.hinweis


def test_audit_unterschaetzt_drastisch() -> None:
    a = bewerte_score_abweichung(40, 85)
    assert a is not None
    assert a.drastisch is True
    assert a.richtung == "unterschaetzt"
    assert "UNTER" in a.hinweis


def test_deckungsgleich() -> None:
    a = bewerte_score_abweichung(70, 70)
    assert a is not None
    assert a.richtung == "deckungsgleich"
    assert a.differenz == 0.0
    assert a.drastisch is False


def test_genau_an_der_schwelle_ist_drastisch() -> None:
    a = bewerte_score_abweichung(50, 50 - DRASTISCH_SCHWELLE)
    assert a is not None
    assert a.drastisch is True
