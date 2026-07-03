"""test_org_assessment_wizard_prefill.

Live-Test-Befund: Reiter „Organisatorische Sicherheit" speichert scheinbar nicht
— der Wizard startete nach jedem Öffnen leer, weil er die zuletzt gespeicherten
Antworten NIE vorbefüllte (kein ``set_data``-Lücke). Folge: erneutes
Speichern aus dem leeren Wizard überschrieb die alten Antworten mit UNBEKANNT.

Roundtrip-Pflicht: Save → neuer Wizard → Antworten müssen wieder
erscheinen. Plus Unit-Abdeckung von ``set_antwort``/``set_antworten`` inkl. der
Invariante: ``UNBEKANNT`` lässt eine N/A-Vorbelegung unberührt
(konkrete Antwort gewinnt, Nicht-Antwort behält die Profil-Vorbelegung).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.security_scoring.application.os_detection_service import STATUS_UNBEKANNT
from tools.security_scoring.domain.org_security import FRAGEN_DSGVO, OrgAntwort
from tools.security_scoring.gui.dialogs import org_assessment_wizard as wiz_mod
from tools.security_scoring.gui.dialogs.org_assessment_wizard import (
    OrgAssessmentWizard,
    _DsgvoSeite,
    _FrageZeile,
)

pytestmark = pytest.mark.gui


class _FakeRepo:
    """In-Memory-Repo mit speichere/lade_letztes-Vertrag."""

    def __init__(self) -> None:
        self._last = None

    def speichere(self, assessment) -> None:  # noqa: ANN001
        self._last = assessment

    def lade_letztes(self):  # noqa: ANN202
        return self._last


@pytest.fixture
def _no_os_probe(monkeypatch):
    """Hält die MFA/PM-Auto-Detection im Wizard-ctor deterministisch + schnell."""
    stub = SimpleNamespace(status=STATUS_UNBEKANNT, detail="")
    monkeypatch.setattr(wiz_mod, "check_windows_hello", lambda: stub)
    monkeypatch.setattr(
        wiz_mod, "check_installed_password_managers", lambda: stub
    )


# ---------------------------------------------------------------------------
# Unit: set_antwort / set_antworten
# ---------------------------------------------------------------------------


def test_set_antwort_setzt_radio(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0])
    zeile.set_antwort(OrgAntwort.JA)
    assert zeile.antwort() == OrgAntwort.JA
    zeile.set_antwort(OrgAntwort.NEIN)
    assert zeile.antwort() == OrgAntwort.NEIN


def test_set_antwort_unbekannt_laesst_na_vorbelegung(app) -> None:
    # eine Nicht-Antwort (UNBEKANNT) darf die N/A-Vorbelegung NICHT
    # zurücksetzen — nur konkrete Antworten gewinnen.
    zeile = _FrageZeile(FRAGEN_DSGVO[0], vorbelegt_na=True)
    assert zeile.antwort() == OrgAntwort.NICHT_ANWENDBAR
    zeile.set_antwort(OrgAntwort.UNBEKANNT)  # no-op
    assert zeile.antwort() == OrgAntwort.NICHT_ANWENDBAR


def test_set_antwort_konkret_schlaegt_na_vorbelegung(app) -> None:
    zeile = _FrageZeile(FRAGEN_DSGVO[0], vorbelegt_na=True)
    zeile.set_antwort(OrgAntwort.JA)  # konkrete Antwort gewinnt
    assert zeile.antwort() == OrgAntwort.JA


def test_seite_set_antworten(app) -> None:
    keys = [f.key for f in FRAGEN_DSGVO]
    seite = _DsgvoSeite()
    seite.set_antworten({keys[0]: OrgAntwort.JA, keys[1]: OrgAntwort.NICHT_ANWENDBAR})
    antworten = seite.sammle_antworten()
    assert antworten[keys[0]] == OrgAntwort.JA
    assert antworten[keys[1]] == OrgAntwort.NICHT_ANWENDBAR
    assert antworten[keys[2]] == OrgAntwort.UNBEKANNT  # ungesetzt bleibt unbekannt


# ---------------------------------------------------------------------------
# Integration: Save → neuer Wizard → Antworten zurück (der eigentliche Bug)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_no_os_probe")
def test_wizard_roundtrip_vorbefuellt_gespeicherte_antworten(app) -> None:
    from tools.security_scoring.application.org_security_service import (
        OrgSecurityService,
    )

    service = OrgSecurityService(_FakeRepo())
    keys = [f.key for f in FRAGEN_DSGVO]

    # Wizard 1: zwei DSGVO-Antworten setzen + speichern.
    w1 = OrgAssessmentWizard(service)
    w1._seite_dsgvo.set_antworten(  # noqa: SLF001
        {keys[0]: OrgAntwort.JA, keys[1]: OrgAntwort.NEIN}
    )
    w1._speichern()  # noqa: SLF001 -- persistiert via Service

    # Wizard 2: frische Instanz, gleicher Service → muss vorbefüllen.
    w2 = OrgAssessmentWizard(service)
    antworten = w2._seite_dsgvo.sammle_antworten()  # noqa: SLF001
    assert antworten[keys[0]] == OrgAntwort.JA
    assert antworten[keys[1]] == OrgAntwort.NEIN


@pytest.mark.usefixtures("_no_os_probe")
def test_wizard_ohne_gespeichertes_startet_frisch(app) -> None:
    from tools.security_scoring.application.org_security_service import (
        OrgSecurityService,
    )

    service = OrgSecurityService(_FakeRepo())  # leer
    w = OrgAssessmentWizard(service)
    antworten = w._seite_dsgvo.sammle_antworten()  # noqa: SLF001
    assert all(a == OrgAntwort.UNBEKANNT for a in antworten.values())


@pytest.mark.usefixtures("_no_os_probe")
def test_wizard_vorbefuellung_fail_soft(app) -> None:
    # Wirft lade_letztes, darf der Wizard NICHT crashen (startet frisch).
    class _BoomRepo(_FakeRepo):
        def lade_letztes(self):  # noqa: ANN202
            raise RuntimeError("DB weg")

    from tools.security_scoring.application.org_security_service import (
        OrgSecurityService,
    )

    # Service.lade_letztes faengt selbst ab -> None; zur Sicherheit auch der
    # Wizard-Pfad ist fail-soft. Test stellt sicher: kein Crash im ctor.
    service = OrgSecurityService(_BoomRepo())
    w = OrgAssessmentWizard(service)
    assert w is not None
