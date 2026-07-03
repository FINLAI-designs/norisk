"""Tests fuer die kuratierte Leitfaden-Registry (c2)."""

from __future__ import annotations

from core.guide_registry import (
    alle_guides,
    fallback_guide,
    guide_exists,
    guide_path,
    guides_root,
    match_guides,
)


def test_alle_sechs_guides_sind_gebuendelt():
    """Die 6 ALLGEMEIN-PDFs liegen tatsaechlich in resources/guides/."""
    guides = alle_guides()
    assert len(guides) == 6
    for g in guides:
        assert guide_exists(g), f"Guide-PDF fehlt: {g.filename}"
        assert guide_path(g).parent == guides_root()


def test_match_backup():
    treffer = match_guides("Regelmäßige Datensicherung einrichten (Backup)")
    assert treffer
    assert treffer[0].key == "backup_321"


def test_match_verschluesselung():
    treffer = match_guides("Festplatte verschlüsseln mit BitLocker")
    assert any(g.key == "verschluesselung" for g in treffer)


def test_match_lieferkette():
    treffer = match_guides("AVV mit Drittanbieter / Lieferant prüfen")
    assert any(g.key == "lieferkette" for g in treffer)


def test_match_grundschutz_als_thematischer_treffer():
    treffer = match_guides("Firewall aktivieren und Updates einspielen")
    assert any(g.key == "grundschutz_kmu" for g in treffer)


def test_kein_match_gibt_leere_liste():
    assert match_guides("völlig unbezogener Text ohne Schlagwort xyz") == []


def test_thematischer_treffer_vor_fallback():
    # "backup" matcht backup_321; grundschutz darf nicht VOR dem Thema kommen.
    treffer = match_guides("backup und passwort", limit=2)
    assert treffer[0].key == "backup_321"


def test_limit_wird_eingehalten():
    # Text der mehrere Themen trifft -> auf limit begrenzt.
    treffer = match_guides("backup verschlüsseln lieferant firewall", limit=2)
    assert len(treffer) == 2


def test_fallback_guide_ist_grundschutz():
    fb = fallback_guide()
    assert fb is not None
    assert fb.key == "grundschutz_kmu"
