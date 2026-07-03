"""test_nis2_phase_form_gui — Headless-GUI-Tests fuer Schicht 2.

Deckt die NIS2-revisionssichere GUI-Schicht ab:

- ``PhaseFormDialog`` rendert die Felder einer Phase + zeigt PII-Hinweis.
- Draft-Roundtrip: speichern → neu oeffnen → geladene Werte erscheinen.
- Einreichen mit fehlendem Pflichtfeld blockt (Inline-Fehler), mit
  vollstaendigem Payload ruft es ``submit_draft`` (Append-only-Event).
- ``build_meldevorlage`` erzeugt die Vorlage MIT Disclaimer + Phasen-Inhalt.
- Personenbezug-Sync setzt das harte Header-Flag.

Die GUI wird offscreen instanziiert (``QT_QPA_PLATFORM=offscreen``); der
Service laeuft gegen eine In-Memory-DB (kein Production-Pfad).

Schichtzugehoerigkeit: tests/ — darf alle Schichten anfassen.

Author: Patrick Riederich
Version: 0.1 (NIS2-revisionssicher, Schicht 2 GUI)
"""

from __future__ import annotations

import sqlite3

import pytest

from tools.customer_audit.application.nis2_incident_service import (
    Nis2IncidentService,
)
from tools.customer_audit.data.nis2_incident_repository import (
    DbNis2IncidentRepository,
)
from tools.customer_audit.domain import nis2_phase_schema
from tools.customer_audit.domain.nis2_incident import (
    IncidentPhase,
    IncidentSeverity,
    PhaseStatus,
)
from tools.customer_audit.domain.nis2_phase_schema import PII_HINWEIS
from tools.nis2_incidents.gui.export_meldevorlage import (
    DISCLAIMER,
    MeldeFrist,
    build_meldevorlage,
)
from tools.nis2_incidents.gui.phase_form_dialog import PhaseFormDialog

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


@pytest.fixture(scope="module")
def qapp():
    """Stellt eine ``QApplication`` fuer alle Tests im Modul bereit."""
    from PySide6.QtWidgets import QApplication  # noqa: PLC0415

    app = QApplication.instance() or QApplication([])
    return app


@pytest.fixture
def service() -> Nis2IncidentService:
    return Nis2IncidentService(
        repository=DbNis2IncidentRepository(db=_InMemoryDB())
    )


@pytest.fixture
def incident(service):
    """Legt einen offenen Vorfall an und schaltet auf NOTIFICATION."""
    inc = service.open_incident(
        audit_id="audit-1",
        title="Ransomware-Verdacht",
        severity=IncidentSeverity.HIGH,
        actor="tester",
    )
    return inc


# ----------------------------------------------------------------------
# PhaseFormDialog — Rendering + PII-Hinweis
# ----------------------------------------------------------------------


def test_dialog_rendert_felder_und_pii_hinweis(qapp, service, incident):
    """Dialog rendert je Schema-Feld ein Widget + zeigt den PII-Hinweis."""
    from PySide6.QtWidgets import QLabel, QWidget  # noqa: PLC0415

    dialog = PhaseFormDialog(
        incident_id=incident.incident_id,
        phase=IncidentPhase.NOTIFICATION,
        service=service,
    )
    fields = nis2_phase_schema.fields_for(IncidentPhase.NOTIFICATION)
    # Pro Schema-Feld muss ein Eingabe-Widget mit ObjectName existieren.
    for field in fields:
        w = dialog.findChild(QWidget, f"field_{field.key}")
        assert w is not None, f"Widget fuer {field.key} fehlt"

    # PII-Hinweis ist mindestens einmal sichtbar (Freitextfelder existieren).
    pii_labels = [
        lbl
        for lbl in dialog.findChildren(QLabel, "lbl_pii_hinweis")
        if PII_HINWEIS in lbl.text()
    ]
    assert pii_labels, "PII-Hinweis wird nicht angezeigt"


def test_dialog_zeigt_sichtbare_phasen_anleitung(qapp, service, incident):
    """Die Phasen-Anleitung steht sichtbar (nicht nur als Tooltip)."""
    from PySide6.QtWidgets import QLabel  # noqa: PLC0415

    dialog = PhaseFormDialog(
        incident_id=incident.incident_id,
        phase=IncidentPhase.EARLY_WARNING,
        service=service,
    )
    guidance = dialog.findChild(QLabel, "lbl_phase_guidance")
    assert guidance is not None
    assert "CSIRT" in guidance.text() or "24h" in guidance.text()


# ----------------------------------------------------------------------
# Draft-Roundtrip
# ----------------------------------------------------------------------


def test_draft_save_reopen_roundtrip(qapp, service, incident):
    """save -> reopen -> geladene Werte erscheinen im Formular."""
    from PySide6.QtWidgets import QPlainTextEdit  # noqa: PLC0415

    phase = IncidentPhase.EARLY_WARNING
    dialog = PhaseFormDialog(incident.incident_id, phase, service)
    # Tristate + Multiline befuellen, dann "Entwurf speichern".
    _set_tristate(dialog, "verdacht_rechtswidrig", "ja")
    _set_tristate(dialog, "grenzueberschreitend", "nein")
    dienste = dialog.findChild(QPlainTextEdit, "field_betroffene_dienste")
    dienste.setPlainText("Mailserver, Fileshare")
    dialog._on_save_draft()  # noqa: SLF001
    assert dialog.chosen_action() == PhaseFormDialog.ACTION_SAVED

    # Neuer Dialog laedt den Draft.
    reopened = PhaseFormDialog(incident.incident_id, phase, service)
    dienste2 = reopened.findChild(QPlainTextEdit, "field_betroffene_dienste")
    assert dienste2.toPlainText() == "Mailserver, Fileshare"
    # Tristate-Werte ebenfalls wiederhergestellt.
    assert _get_tristate(reopened, "verdacht_rechtswidrig") == "ja"
    assert _get_tristate(reopened, "grenzueberschreitend") == "nein"


# ----------------------------------------------------------------------
# Einreichen — Validierung
# ----------------------------------------------------------------------


def test_submit_blockt_bei_fehlendem_pflichtfeld(qapp, service, incident):
    """Einreichen ohne Pflichtfelder zeigt Inline-Fehler, kein Event."""
    from PySide6.QtWidgets import QLabel  # noqa: PLC0415

    phase = IncidentPhase.EARLY_WARNING
    dialog = PhaseFormDialog(incident.incident_id, phase, service)
    dialog._on_submit()  # noqa: SLF001
    assert dialog.chosen_action() == PhaseFormDialog.ACTION_NONE
    err = dialog.findChild(QLabel, "lbl_phase_error")
    # isVisibleTo(parent) reflektiert das explizite Visible-Flag auch ohne
    # show des Top-Level-Dialogs (offscreen).
    assert err is not None and err.isVisibleTo(dialog)
    assert "Pflichtfelder" in err.text()
    # Kein neues Phasen-Event geschrieben (nur das initiale DETECT-Event).
    reloaded = service.load_incident(incident.incident_id)
    ew_events = [
        e for e in reloaded.events if e.phase is IncidentPhase.EARLY_WARNING
    ]
    assert ew_events == []


def test_submit_vollstaendig_schreibt_event(qapp, service, incident):
    """Vollstaendiges Formular -> submit_draft -> Append-only-Event."""
    phase = IncidentPhase.EARLY_WARNING
    dialog = PhaseFormDialog(incident.incident_id, phase, service)
    _set_tristate(dialog, "verdacht_rechtswidrig", "ja")
    _set_tristate(dialog, "grenzueberschreitend", "unbekannt")
    _set_multiline(dialog, "betroffene_dienste", "Fileshare betroffen")
    dialog._on_submit()  # noqa: SLF001
    assert dialog.chosen_action() == PhaseFormDialog.ACTION_SUBMIT

    reloaded = service.load_incident(incident.incident_id)
    ew_events = [
        e for e in reloaded.events if e.phase is IncidentPhase.EARLY_WARNING
    ]
    assert len(ew_events) == 1
    event = ew_events[0]
    assert event.status is PhaseStatus.DONE
    assert event.payload.get("verdacht_rechtswidrig") == "ja"
    assert event.payload.get("betroffene_dienste") == "Fileshare betroffen"
    # submit_draft schreibt nur EIN Event; der Header schaltet (ohne zweites
    # Event) auf die naechste Phase weiter §2).
    assert reloaded.current_phase is IncidentPhase.NOTIFICATION


# ----------------------------------------------------------------------
# Personenbezug-Sync (NOTIFICATION)
# ----------------------------------------------------------------------


def test_personenbezug_sync_setzt_header_flag(qapp, service, incident):
    """NOTIFICATION mit personenbezug=True synchronisiert das Header-Flag."""
    from PySide6.QtWidgets import QCheckBox  # noqa: PLC0415

    phase = IncidentPhase.NOTIFICATION
    dialog = PhaseFormDialog(incident.incident_id, phase, service)
    _set_text(dialog, "schweregrad", "high")
    _set_multiline(dialog, "impact_verfuegbarkeit", "2h Ausfall Mailserver")
    _set_multiline(dialog, "erste_ursache", "Phishing vermutet")
    pb = dialog.findChild(QCheckBox, "field_personenbezug")
    pb.setChecked(True)
    dialog._on_submit()  # noqa: SLF001
    assert dialog.chosen_action() == PhaseFormDialog.ACTION_SUBMIT

    reloaded = service.load_incident(incident.incident_id)
    assert reloaded.personenbezug is True
    # P0: set_personenbezug(True) NACH dem Submit darf die HMAC-Kette NICHT
    # brechen (personenbezug ist Header-Flag, kein Event-Inhalt mehr).
    assert service.verify_chain(incident.incident_id) == (True, None)


# ----------------------------------------------------------------------
# Export-Meldevorlage (GUI-frei)
# ----------------------------------------------------------------------


def test_build_meldevorlage_hat_disclaimer_und_inhalt(service, incident):
    """Vorlage traegt den Disclaimer oben + die Phasen-Payloads lesbar."""
    payloads = {
        IncidentPhase.EARLY_WARNING: {
            "verdacht_rechtswidrig": "ja",
            "grenzueberschreitend": "nein",
            "betroffene_dienste": "Mailserver",
        },
        IncidentPhase.NOTIFICATION: {
            "schweregrad": "high",
            "impact_verfuegbarkeit": "2h Ausfall",
            "erste_ursache": "Phishing",
            "personenbezug": True,
            "iocs": ["1.2.3.4", "evil.example"],
        },
    }
    text = build_meldevorlage(
        incident, MeldeFrist.MELDUNG_72H, payloads
    )
    # Disclaimer ganz oben.
    assert text.startswith(DISCLAIMER)
    assert "KEINE Meldung" in text
    # Lesbar gelabelter Phasen-Inhalt (Label aus dem Schema, nicht der key).
    assert "Schweregrad" in text
    assert "high" in text
    assert "Betroffene Dienste/Systeme" in text
    assert "Mailserver" in text
    # Listen werden zusammengefuehrt.
    assert "1.2.3.4, evil.example" in text
    # Bool wird lesbar gerendert.
    assert "Ja" in text


def test_build_meldevorlage_24h_ignoriert_spaetere_phasen(service, incident):
    """Die 24h-Vorlage enthaelt keine NOTIFICATION-Felder."""
    payloads = {
        IncidentPhase.EARLY_WARNING: {"betroffene_dienste": "Webshop"},
        IncidentPhase.NOTIFICATION: {"schweregrad": "critical"},
    }
    text = build_meldevorlage(
        incident, MeldeFrist.FRUEHWARNUNG_24H, payloads
    )
    assert "Webshop" in text
    assert "critical" not in text


# ----------------------------------------------------------------------
# Test-Helfer
# ----------------------------------------------------------------------


def _set_tristate(dialog, key, value) -> None:
    from PySide6.QtWidgets import QComboBox  # noqa: PLC0415

    w = dialog.findChild(QComboBox, f"field_{key}")
    idx = w.findData(value)
    assert idx >= 0, f"Tristate-Wert {value} nicht gefunden"
    w.setCurrentIndex(idx)


def _get_tristate(dialog, key) -> str:
    from PySide6.QtWidgets import QComboBox  # noqa: PLC0415

    w = dialog.findChild(QComboBox, f"field_{key}")
    return str(w.currentData() or "")


def _set_multiline(dialog, key, value) -> None:
    from PySide6.QtWidgets import QPlainTextEdit  # noqa: PLC0415

    w = dialog.findChild(QPlainTextEdit, f"field_{key}")
    w.setPlainText(value)


def _set_text(dialog, key, value) -> None:
    from PySide6.QtWidgets import QLineEdit  # noqa: PLC0415

    w = dialog.findChild(QLineEdit, f"field_{key}")
    w.setText(value)
