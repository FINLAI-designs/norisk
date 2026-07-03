""" UI-Erkennbarkeit — Regressionsnetz für die geschlossenen „partiell"-Lücken.

Deckt drei Befunde aus dem-UI-Audit ab (Wireshark/Stratoshark-Epic):

  - **F-A:** Die §202c-Schranke (und jede ``ValidationError``) wird als
    prominenter modaler Hinweis gezeigt, nicht nur im leicht zu übersehenden
    rechtsbündigen Status-Label. Es wird KEIN GUI-Pfad für externe Scans
    geschaffen — die Internal-only-Policy bleibt unangetastet.
  - **F-B:** Der TLS-Banner ist eine sichtbare Spalte der Port-Tabelle
    (vorher nur nach einem Klick im Detail-Panel erkennbar).
  - **F-D:** Der Bedrohungslisten-Tab zeigt einen ehrlichen First-Run-Hinweis,
    dass die lokale Liste bis zum ersten Online-Abgleich leer ist.

Author: Patrick Riederich
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from core.exceptions import ValidationError
from tools.network_scanner.application.network_service import NetworkService
from tools.network_scanner.domain.models import (
    HostInfo,
    NetworkScanResult,
    PortInfo,
    PortRisk,
    PortState,
)
from tools.network_scanner.gui.network_scanner_widget import (
    NetworkScannerWidget,
    _ScanThread,
)


def _make_scanner_widget(qtbot) -> NetworkScannerWidget:
    """Baut das Scanner-Widget mit einem Service-Mock (kein Netz)."""
    service = MagicMock(spec=NetworkService)
    service.eigene_netzwerk_info.return_value = ("", "", "")
    service.nmap_verfuegbar.return_value = False
    widget = NetworkScannerWidget(service)
    qtbot.add_widget(widget)
    return widget


class TestFaProminenterHinweis:
    """F-A: ValidationError → prominenter modaler Hinweis, nicht nur Status-Label."""

    def test_scanthread_routet_validation_error_auf_validierung(self, qtbot):  # noqa: ARG002
        """Eine ValidationError landet auf ``validierung``, NICHT auf ``fehler``."""
        service = MagicMock(spec=NetworkService)
        service.starte_scan.side_effect = ValidationError(
            "'8.8.8.8' ist kein internes Ziel (Pentest-Auftrag erforderlich, "
            "§202c StGB)."
        )
        thread = _ScanThread(service=service, ziel="8.8.8.8", nmap=False)
        captured: dict[str, str] = {}
        thread.validierung.connect(lambda m: captured.__setitem__("val", m))
        thread.fehler.connect(lambda m: captured.__setitem__("err", m))
        thread.ergebnis.connect(lambda _r: captured.__setitem__("ok", "1"))

        thread.run()  # synchron im Test-Thread — kein start

        assert "val" in captured, "ValidationError muss validierung emittieren"
        assert "§202c" in captured["val"]
        assert "err" not in captured, "darf NICHT als technischer Fehler laufen"
        assert "ok" not in captured

    def test_slot_zeigt_modalen_plaintext_hinweis(self, qtbot, monkeypatch):
        """Der Slot zeigt einen prominenten Dialog — und zwar als PlainText (R22).

        Dialog-Migration: statt der nativen ``QMessageBox`` zeigt der Slot nun
        den FINLAI-konformen ``FinlaiInfoDialog`` (core/dialogs.py). Dessen
        Nachricht wird intern fest als PlainText gerendert (
        ``FinlaiInfoDialog._build_ui`` → ``setTextFormat(PlainText)``), sodass
        ein vom User eingegebenes Ziel mit Markup nie als RichText interpretiert
        wird (R22). Wir patchen die Klasse als ``MagicMock`` und prüfen, dass sie
        mit der §202c-Begründung instanziiert und ihr ``.exec`` aufgerufen wird.
        """
        from PySide6.QtWidgets import QMessageBox

        from tools.network_scanner.gui import network_scanner_widget

        widget = _make_scanner_widget(qtbot)

        # Schutznetz gegen Rück-Migration: würde der Code wieder eine native
        # QMessageBox bauen, fiele dieser Test NICHT mehr auf den Dialog zurück.
        assert not hasattr(network_scanner_widget, "QMessageBox"), (
            "Slot soll den FinlaiInfoDialog nutzen, nicht die native QMessageBox"
        )
        # ``self.text`` existiert auf QMessageBox; der FinlaiInfoDialog hat es
        # nicht — sicherstellen, dass wir nichts versehentlich darauf abstützen.
        assert not hasattr(QMessageBox, "_finlai_patched")

        dlg_mock = MagicMock(name="FinlaiInfoDialog")
        monkeypatch.setattr(network_scanner_widget, "FinlaiInfoDialog", dlg_mock)

        # Ziel mit Markup: der Dialog rendert intern PlainText, daher wird das
        # Markup nie interpretiert (R22). Wir reichen es roh durch und prüfen,
        # dass exakt dieser Text an den Dialog übergeben wird.
        roh_msg = "Ungültiges Scan-Ziel: '<b>8.8.8.8' (..., §202c StGB)."
        widget._scan_validierung_fehlgeschlagen(roh_msg)

        # Dialog wurde instanziiert (prominenter modaler Hinweis erscheint).
        assert dlg_mock.call_count == 1, "Es muss genau ein modaler Hinweis erscheinen"
        _args, kwargs = dlg_mock.call_args
        assert kwargs.get("message") == roh_msg, (
            "Begründung (inkl. §202c) muss unverändert in den Dialog gehen"
        )
        assert "§202c" in kwargs.get("message", ""), "Begründung muss im Dialog stehen"
        # Und der Hinweis wird auch tatsächlich angezeigt (.exec).
        dlg_mock.return_value.exec.assert_called_once()

        assert "Hinweis" in widget._lbl_status.text()

    def test_kein_extern_erlaubt_pfad_im_widget(self):
        """Schutznetz: das Widget verdrahtet ``extern_erlaubt`` nirgends auf True."""
        import re

        from tools.network_scanner.gui import network_scanner_widget

        src = Path(network_scanner_widget.__file__).read_text(encoding="utf-8")
        assert re.search(r"extern_erlaubt\s*=\s*True", src) is None


class TestFbBannerSpalte:
    """F-B: TLS-Banner als sichtbare Tabellen-Spalte statt nur im Detail-Klick."""

    def test_port_tabelle_hat_banner_spalte(self, qtbot):
        widget = _make_scanner_widget(qtbot)
        assert widget._port_tree.columnCount() == 5
        assert widget._port_tree.headerItem().text(4) == "Banner"

    def test_banner_wird_in_der_zeile_angezeigt(self, qtbot):
        widget = _make_scanner_widget(qtbot)
        banner = "TLSv1.3 TLS_AES_256_GCM_SHA384 h2"
        port = PortInfo(
            port=443,
            state=PortState.OPEN,
            service="https",
            banner=banner,
            risk=PortRisk.INFO,
            hinweis="",
        )
        host = HostInfo(host="192.168.1.1", erreichbar=True, offene_ports=[port])
        now = datetime.now(UTC)
        result = NetworkScanResult(
            ziel="192.168.1.1",
            hosts=[host],
            gestartet_am=now,
            beendet_am=now,
            scanner_typ="socket",
        )

        widget._scan_ergebnis_empfangen(result)

        item = widget._port_tree.topLevelItem(0)
        assert item is not None
        assert item.text(4) == banner
        # Volltext-Tooltip für ggf. abgeschnittene lange Banner.
        assert item.toolTip(4) == banner

    def test_leerer_banner_zeigt_platzhalter(self, qtbot):
        widget = _make_scanner_widget(qtbot)
        port = PortInfo(
            port=22, state=PortState.OPEN, service="ssh", banner="",
            risk=PortRisk.HOCH, hinweis="SSH offen",
        )
        host = HostInfo(host="10.0.0.5", erreichbar=True, offene_ports=[port])
        now = datetime.now(UTC)
        result = NetworkScanResult(
            ziel="10.0.0.5", hosts=[host], gestartet_am=now,
            beendet_am=now, scanner_typ="socket",
        )

        widget._scan_ergebnis_empfangen(result)

        item = widget._port_tree.topLevelItem(0)
        assert item.text(4) == "—"

    def test_banner_mit_markup_wird_im_tooltip_escaped(self, qtbot):
        """Server-kontrolliertes Banner mit Markup wird nicht als RichText gerendert (R22)."""
        widget = _make_scanner_widget(qtbot)
        roh = "<b>Server</b> 1.0"
        port = PortInfo(
            port=80, state=PortState.OPEN, service="http", banner=roh,
            risk=PortRisk.MITTEL, hinweis="",
        )
        host = HostInfo(host="192.168.1.1", erreichbar=True, offene_ports=[port])
        now = datetime.now(UTC)
        result = NetworkScanResult(
            ziel="192.168.1.1", hosts=[host], gestartet_am=now,
            beendet_am=now, scanner_typ="socket",
        )

        widget._scan_ergebnis_empfangen(result)

        item = widget._port_tree.topLevelItem(0)
        assert item.toolTip(4) == html.escape(roh)
        assert "<b>" not in item.toolTip(4)


class TestFdFirstRunHinweis:
    """F-D: ehrlicher First-Run-Hinweis zur (initial leeren) lokalen Liste."""

    def test_threat_tab_zeigt_first_run_hinweis(self, qtbot, tmp_path: Path):
        from tools.network_monitor.application.whitelist_service import (
            WhitelistService,
        )
        from tools.network_monitor.gui.threat_list_tab import ThreatListTab

        svc = WhitelistService(whitelist_path=tmp_path / "wl.txt")
        tab = ThreatListTab(
            whitelist_service=svc, refresh_service_factory=lambda: None
        )
        qtbot.add_widget(tab)

        text = tab._refresh_status.text()
        assert text, "Status-Label darf beim Start nicht leer sein"
        assert "lokale Bedrohungsliste" in text
        assert "Online-Abgleich" in text
