"""
test_techstack_widget — GUI-Verhalten des Empty-States im Techstack-Widget.

Absichert:
  - Leerer Stack zeigt Hinweistext und Starter-Button.
  - Klick auf Starter-Button fügt AT_STARTER_STACK-Einträge via Service
    hinzu und setzt eine Status-Meldung.
  - Befüllter Stack versteckt den Empty-State.

Seit 2026-04-20 ist Techstack ein eigenständiges Tool (vorher Tab 4 in
:mod:`tools.cyber_dashboard`); dieser Test migriert aus
``tests/tools/cyber_dashboard/test_techstack_tab.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QDialog

from tools.cyber_dashboard.data.techstack_repository import AT_STARTER_STACK
from tools.cyber_dashboard.domain.models import TechStackEintrag, TechStackKandidat
from tools.techstack.gui import techstack_import_dialog as dlg_mod
from tools.techstack.gui.techstack_import_dialog import TechStackImportDialog
from tools.techstack.gui.techstack_widget import TechStackWidget

pytestmark = pytest.mark.gui


@pytest.fixture()
def service_leer() -> MagicMock:
    """Service-Mock der einen leeren Techstack liefert."""
    svc = MagicMock()
    svc.lade_techstack.return_value = []
    svc.nvd_aktiv.return_value = False
    # GUI fragt die Starter-Liste jetzt via Service, nicht
    # mehr per Direkt-Import von AT_STARTER_STACK.
    svc.get_at_starter_stack.return_value = list(AT_STARTER_STACK)
    return svc


@pytest.fixture()
def service_mit_eintraegen() -> MagicMock:
    """Service-Mock der den AT-Starter-Stack als geladen liefert."""
    svc = MagicMock()
    svc.lade_techstack.return_value = list(AT_STARTER_STACK)
    svc.nvd_aktiv.return_value = False
    svc.get_at_starter_stack.return_value = list(AT_STARTER_STACK)
    return svc


class TestEmptyState:
    """Empty-State ist nur bei leerem Stack sichtbar."""

    def test_empty_state_sichtbar_bei_leerem_stack(
        self, qtbot, service_leer: MagicMock
    ) -> None:
        widget = TechStackWidget(service_leer)
        qtbot.addWidget(widget)
        widget.show()
        assert widget._empty_state.isVisible()
        assert widget._btn_starter.isVisible()
        assert "leer" in widget._lbl_empty_hint.text()

    def test_empty_state_versteckt_bei_befuelltem_stack(
        self, qtbot, service_mit_eintraegen: MagicMock
    ) -> None:
        widget = TechStackWidget(service_mit_eintraegen)
        qtbot.addWidget(widget)
        widget.show()
        assert not widget._empty_state.isVisible()


class TestStarterButton:
    """Starter-Button lädt die Vorschlagsliste ausschließlich auf Klick."""

    def test_klick_fuellt_stack_via_service(
        self, qtbot, service_leer: MagicMock
    ) -> None:
        widget = TechStackWidget(service_leer)
        qtbot.addWidget(widget)
        widget.show()

        # Nach Klick liefert der Service die 8 Starter-Einträge zurück.
        service_leer.lade_techstack.return_value = list(AT_STARTER_STACK)
        widget._btn_starter.click()

        assert service_leer.techstack_hinzufuegen.call_count == len(AT_STARTER_STACK)
        uebernommene = [
            c.args[0] for c in service_leer.techstack_hinzufuegen.call_args_list
        ]
        assert [e.name for e in uebernommene] == [e.name for e in AT_STARTER_STACK]

    def test_klick_zeigt_status_und_versteckt_empty_state(
        self, qtbot, service_leer: MagicMock
    ) -> None:
        widget = TechStackWidget(service_leer)
        qtbot.addWidget(widget)
        widget.show()

        service_leer.lade_techstack.return_value = list(AT_STARTER_STACK)
        widget._btn_starter.click()

        assert not widget._empty_state.isVisible()
        assert str(len(AT_STARTER_STACK)) in widget._lbl_stack_status.text()
        assert "Vorschlagsliste" in widget._lbl_stack_status.text()


# ---------------------------------------------------------------------------
# Import-Vorschau-Dialog + Sync-Übernahme im Widget
# ---------------------------------------------------------------------------


def _kandidaten() -> list[TechStackKandidat]:
    return [
        TechStackKandidat(
            TechStackEintrag(name="Python", version="3.12", cpe="cpe:py"),
            ("System-Scan",),
        ),
        TechStackKandidat(
            TechStackEintrag(name="Apache"), ("Patch-Monitor",)
        ),
    ]


class TestImportDialog:
    """Vorschau-Dialog liefert nur die angehakten Einträge."""

    def test_default_alle_ausgewaehlt(self, qtbot) -> None:
        dlg = TechStackImportDialog(_kandidaten())
        qtbot.addWidget(dlg)
        assert [e.name for e in dlg.ausgewaehlte_eintraege()] == ["Python", "Apache"]

    def test_einzelne_abwahl(self, qtbot) -> None:
        dlg = TechStackImportDialog(_kandidaten())
        qtbot.addWidget(dlg)
        dlg._checkboxen[0][0].setChecked(False)  # Python abwählen
        assert [e.name for e in dlg.ausgewaehlte_eintraege()] == ["Apache"]

    def test_alle_schalter_aus(self, qtbot) -> None:
        dlg = TechStackImportDialog(_kandidaten())
        qtbot.addWidget(dlg)
        dlg._alle_cb.setChecked(False)
        assert dlg.ausgewaehlte_eintraege() == []
        dlg._alle_cb.setChecked(True)
        assert len(dlg.ausgewaehlte_eintraege()) == 2


class TestSyncUebernahme:
    """„Aus System-Scan & Patch-Monitor übernehmen"-Button."""

    def _service(self) -> MagicMock:
        svc = MagicMock()
        svc.lade_techstack.return_value = []
        svc.nvd_aktiv.return_value = False
        svc.get_at_starter_stack.return_value = []
        return svc

    def test_leere_kandidaten_zeigt_hinweis(self, qtbot) -> None:
        svc = self._service()
        svc.techstack_sync_kandidaten.return_value = []
        widget = TechStackWidget(svc)
        qtbot.addWidget(widget)
        widget.show()

        widget._btn_sync.click()

        assert "Keine neuen Produkte" in widget._lbl_stack_status.text()
        svc.techstack_uebernehmen.assert_not_called()

    def test_uebernahme_ruft_service_und_aktualisiert(
        self, qtbot, monkeypatch
    ) -> None:
        svc = self._service()
        kandidat = _kandidaten()[1]  # Apache
        svc.techstack_sync_kandidaten.return_value = [kandidat]
        svc.techstack_uebernehmen.return_value = 1

        fake_dlg = MagicMock()
        fake_dlg.exec.return_value = QDialog.DialogCode.Accepted
        fake_dlg.ausgewaehlte_eintraege.return_value = [kandidat.eintrag]
        monkeypatch.setattr(
            dlg_mod, "TechStackImportDialog", lambda *a, **k: fake_dlg
        )

        widget = TechStackWidget(svc)
        qtbot.addWidget(widget)
        widget.show()
        widget._btn_sync.click()

        svc.techstack_uebernehmen.assert_called_once_with([kandidat.eintrag])
        assert "1 Eintrag" in widget._lbl_stack_status.text()

    def test_abbruch_uebernimmt_nichts(self, qtbot, monkeypatch) -> None:
        svc = self._service()
        svc.techstack_sync_kandidaten.return_value = _kandidaten()

        fake_dlg = MagicMock()
        fake_dlg.exec.return_value = QDialog.DialogCode.Rejected
        monkeypatch.setattr(
            dlg_mod, "TechStackImportDialog", lambda *a, **k: fake_dlg
        )

        widget = TechStackWidget(svc)
        qtbot.addWidget(widget)
        widget.show()
        widget._btn_sync.click()

        svc.techstack_uebernehmen.assert_not_called()
