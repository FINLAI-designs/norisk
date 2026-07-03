"""test_avv_conformity — Art.-28-Vollstaendigkeits-Pruefung.

Reine Domain-Logik (kein QApplication, keine DB): aus einer AVV-Checkliste
ableiten, wie viele Pflichtinhalte dokumentiert sind, welche fehlen und welche
fehlenden sicherheits-/compliance-kritisch sind. KEINE Rechtsberatung.
"""

from __future__ import annotations

from tools.supply_chain_monitor.domain.avv_conformity import (
    SECURITY_CRITICAL_CLAUSES,
    VERDICT_COMPLETE,
    VERDICT_CRITICAL,
    VERDICT_GAPS,
    assess_art28_conformity,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvChecklistEntry,
)


def _entry(check: Art28Check, present: bool | None) -> AvvChecklistEntry:
    return AvvChecklistEntry(id=None, avv_id=1, is_present=present, art28_check=check)


def _all(present: bool | None) -> list[AvvChecklistEntry]:
    return [_entry(c, present) for c in Art28Check]


def test_alle_dokumentiert_ist_vollstaendig() -> None:
    conf = assess_art28_conformity(_all(True))
    assert conf.verdict == VERDICT_COMPLETE
    assert conf.present_count == len(Art28Check)
    assert conf.missing == ()
    assert conf.security_gaps == ()
    assert conf.is_complete is True


def test_leere_checkliste_ist_kritisch() -> None:
    conf = assess_art28_conformity([])
    assert conf.present_count == 0
    assert conf.verdict == VERDICT_CRITICAL  # security-critical fehlen alle
    assert set(conf.security_gaps) == set(SECURITY_CRITICAL_CLAUSES)
    assert len(conf.missing) == len(Art28Check)


def test_ungeprueft_zaehlt_nicht_als_dokumentiert() -> None:
    conf = assess_art28_conformity(_all(None))
    assert conf.present_count == 0
    assert conf.verdict == VERDICT_CRITICAL


def test_nur_unkritische_luecke_ist_lueckenhaft() -> None:
    # Alle dokumentiert AUSSER DPIA_HILFE (nicht sicherheitskritisch).
    entries = [
        _entry(c, c is not Art28Check.DPIA_HILFE) for c in Art28Check
    ]
    conf = assess_art28_conformity(entries)
    assert conf.verdict == VERDICT_GAPS
    assert conf.missing == (Art28Check.DPIA_HILFE,)
    assert conf.security_gaps == ()


def test_fehlende_toms_ist_kritisch() -> None:
    # Alles dokumentiert ausser TOMs (Art.28(3)(c)) -> kritisch.
    entries = [_entry(c, c is not Art28Check.TOMS) for c in Art28Check]
    conf = assess_art28_conformity(entries)
    assert conf.verdict == VERDICT_CRITICAL
    assert Art28Check.TOMS in conf.security_gaps


def test_custom_eintraege_zaehlen_nicht() -> None:
    entries = [*_all(True), AvvChecklistEntry(
        id=None, avv_id=1, is_present=True, custom_label="Eigener Punkt",
        is_custom=True,
    )]
    conf = assess_art28_conformity(entries)
    # Custom-Eintrag erhoeht present_count NICHT ueber die 10 Pflichtinhalte.
    assert conf.present_count == len(Art28Check)
    assert conf.total == len(Art28Check)
