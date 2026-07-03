"""test_nis2_meldevorlage_pdf — NIS2-Meldevorlage als PDF + Pflichtangaben.

Prueft die richtlinienkonforme Erweiterung der NIS2-Meldevorlage:
- ``meldung_pflicht_luecken`` ermittelt fehlende Art.-23-Pflichtangaben je Frist.
- ``build_meldevorlage_pdf`` erzeugt ein nicht-leeres PDF (Smoke), auch wenn
  Pflichtangaben fehlen (der Status erscheint dann im PDF).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    Nis2Incident,
)
from tools.nis2_incidents.gui.export_meldevorlage import (
    MeldeFrist,
    build_meldevorlage_pdf,
    meldung_pflicht_luecken,
)


def _incident(*, personenbezug: bool = False) -> Nis2Incident:
    return Nis2Incident(
        incident_id="inc-1",
        audit_id="audit-1",
        title="Ransomware-Verdacht",
        description="",
        severity=IncidentSeverity.HIGH,
        detected_at=datetime(2026, 6, 28, 6, 0, tzinfo=UTC),
        current_phase=IncidentPhase.NOTIFICATION,
        personenbezug=personenbezug,
    )


_COMPLETE_24H: dict[IncidentPhase, dict] = {
    IncidentPhase.DETECT: {"kenntnisnahme_zeitpunkt": "2026-06-28T06:00"},
    IncidentPhase.TRIAGE: {
        "ersteinschaetzung": "Verdacht auf Ransomware",
        "erheblich": "ja",
    },
    IncidentPhase.EARLY_WARNING: {
        "verdacht_rechtswidrig": "ja",
        "grenzueberschreitend": "nein",
        "betroffene_dienste": "Webshop",
    },
}


def test_pflicht_luecken_leer_payload_meldet_fehlend() -> None:
    luecken = meldung_pflicht_luecken(MeldeFrist.FRUEHWARNUNG_24H, {})
    # Mind. die EARLY_WARNING-Pflichtfelder fehlen.
    assert IncidentPhase.EARLY_WARNING in luecken
    assert luecken[IncidentPhase.EARLY_WARNING]  # nicht leer


def test_pflicht_luecken_vollstaendig_ist_leer() -> None:
    luecken = meldung_pflicht_luecken(
        MeldeFrist.FRUEHWARNUNG_24H, _COMPLETE_24H
    )
    assert luecken == {}


def test_pflicht_luecken_72h_braucht_notification_felder() -> None:
    # 24h-Felder komplett, aber NOTIFICATION (72h) leer -> Luecke.
    luecken = meldung_pflicht_luecken(MeldeFrist.MELDUNG_72H, _COMPLETE_24H)
    assert IncidentPhase.NOTIFICATION in luecken


def test_build_pdf_erzeugt_nicht_leeres_pdf(tmp_path: Path) -> None:
    out = tmp_path / "meldung.pdf"
    result = build_meldevorlage_pdf(
        _incident(), MeldeFrist.FRUEHWARNUNG_24H, _COMPLETE_24H, out
    )
    assert result == out
    assert out.exists()
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 1000


def test_build_pdf_mit_luecken_und_personenbezug_kein_crash(
    tmp_path: Path,
) -> None:
    out = tmp_path / "meldung_unvollstaendig.pdf"
    # Leere Payloads -> Pflichtangaben-Status zeigt Luecken; Personenbezug ->
    # DSGVO-Sektion. Darf nicht crashen.
    build_meldevorlage_pdf(
        _incident(personenbezug=True), MeldeFrist.ABSCHLUSS_30D, {}, out
    )
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF")
