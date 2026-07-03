"""test_org_assessment_wizard_na.

Der 3er-Radio-Wizard (Ja / Nein / „trifft nicht zu") erzeugt
JA/NEIN/NICHT_ANWENDBAR; eine unbeantwortete Frage → UNBEKANNT.

Roundtrip-Pflicht (Step-Widget-Roundtrip): die GUI ist die einzige
Quelle der OrgAntwort-Werte (``sammle_antworten``) — N/A muss hier korrekt
entstehen, sonst landet es nie im Score/in der Persistenz.

Bezug: [[-org-scoring-na-semantik]].
"""

from __future__ import annotations

import pytest

from tools.security_scoring.domain.org_security import FRAGEN_DSGVO, OrgAntwort
from tools.security_scoring.gui.dialogs.org_assessment_wizard import (
    _DsgvoSeite,
    _FrageZeile,
)

pytestmark = pytest.mark.gui


def test_fragezeile_unbeantwortet_ist_unbekannt(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0])
    assert zeile.antwort() == OrgAntwort.UNBEKANNT


def test_fragezeile_na_auswahl(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0])
    zeile._radios[OrgAntwort.NICHT_ANWENDBAR].setChecked(True)  # noqa: SLF001
    assert zeile.antwort() == OrgAntwort.NICHT_ANWENDBAR


def test_fragezeile_ja_und_nein(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0])
    zeile._radios[OrgAntwort.JA].setChecked(True)  # noqa: SLF001
    assert zeile.antwort() == OrgAntwort.JA
    # Exklusive Gruppe: NEIN wählen wechselt den Zustand.
    zeile._radios[OrgAntwort.NEIN].setChecked(True)  # noqa: SLF001
    assert zeile.antwort() == OrgAntwort.NEIN


def test_seite_sammelt_gemischte_zustaende(app) -> None:
    seite = _DsgvoSeite()
    keys = list(seite._fragen_zeilen.keys())  # noqa: SLF001
    seite._fragen_zeilen[keys[0]]._radios[OrgAntwort.JA].setChecked(True)  # noqa: SLF001
    seite._fragen_zeilen[keys[1]]._radios[  # noqa: SLF001
        OrgAntwort.NICHT_ANWENDBAR
    ].setChecked(True)

    antworten = seite.sammle_antworten()
    assert antworten[keys[0]] == OrgAntwort.JA
    assert antworten[keys[1]] == OrgAntwort.NICHT_ANWENDBAR
    # Rest unbeantwortet → UNBEKANNT (zählt im Nenner, MS-Stil).
    assert antworten[keys[2]] == OrgAntwort.UNBEKANNT


# ---------------------------------------------------------------------------
# Ebene 2 — profil-bedingte N/A-Vorbelegung
# ---------------------------------------------------------------------------


def test_fragezeile_vorbelegt_na(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0], vorbelegt_na=True)
    assert zeile.antwort() == OrgAntwort.NICHT_ANWENDBAR


def test_seite_belegt_na_keys_vor(app) -> None:
    # na_keys = {erste DSGVO-Frage} → vorbelegt N/A; Rest unbeantwortet → UNBEKANNT.
    keys = [f.key for f in FRAGEN_DSGVO]
    seite = _DsgvoSeite(na_keys=frozenset({keys[0]}))
    antworten = seite.sammle_antworten()
    assert antworten[keys[0]] == OrgAntwort.NICHT_ANWENDBAR
    assert antworten[keys[1]] == OrgAntwort.UNBEKANNT


# ---------------------------------------------------------------------------
# Ebene 3 — differenzierter Tooltip (Nutzung vs. Firmengröße)
# ---------------------------------------------------------------------------


def test_nutzungs_vorbelegung_zeigt_datierten_tooltip(app) -> None:
    # avv_abgeschlossen ist nutzungs-bedingt vorbelegt → Nutzungs-Tooltip mit Datum.
    seite = _DsgvoSeite(
        na_keys=frozenset({"avv_abgeschlossen"}),
        na_nutzungs_keys=frozenset({"avv_abgeschlossen"}),
        na_audit_datum="2026-06-05T10:00:00",
    )
    zeile = seite._fragen_zeilen["avv_abgeschlossen"]  # noqa: SLF001
    assert zeile.antwort() == OrgAntwort.NICHT_ANWENDBAR
    tooltip = zeile.toolTip()
    assert "Sovereignty-Audit" in tooltip
    assert "2026-06-05" in tooltip
    assert "Firmengröße" not in tooltip


def test_firmengroesse_vorbelegung_zeigt_groessen_tooltip(app) -> None:
    # na_keys ohne Nutzungs-Markierung → Firmengrößen-Tooltip (Ebene 2 unverändert).
    seite = _DsgvoSeite(na_keys=frozenset({"avv_abgeschlossen"}))
    zeile = seite._fragen_zeilen["avv_abgeschlossen"]  # noqa: SLF001
    assert "Firmengröße" in zeile.toolTip()
