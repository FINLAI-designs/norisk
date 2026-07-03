"""GUI-Tests für die Cross-Tool-Deep-Links (Sprint S3d).

Pro Receiver (``apply_navigation``): Setzt direkt das Eingabefeld.
Pro Trigger (Kontextmenue): Indirekt via ``navigate_to``-Mock auf
``self.window`` -- wir patchen die ``window``-Methode der jeweiligen
Source-Klasse, damit der Aufruf-Pfad isoliert ist.

Plus: ``_build_url``-Helfer im network_scanner.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.network_scanner.gui.network_scanner_widget import NetworkScannerWidget

pytestmark = pytest.mark.gui

# ---------------------------------------------------------------------------
# api_security.apply_navigation(url=...)
# ---------------------------------------------------------------------------


def test_api_security_apply_navigation_setzt_url(qtbot, app):  # noqa: ARG001
    """``apply_navigation(url=...)`` füllt das URL-Feld."""
    from tools.api_security.gui.api_security_widget import ApiSecurityWidget

    widget = ApiSecurityWidget()
    qtbot.add_widget(widget)
    widget.apply_navigation(url="https://api.example.com")
    assert widget._url_input.text() == "https://api.example.com"  # noqa: SLF001


def test_api_security_apply_navigation_leerstring_keine_aenderung(
    qtbot, app  # noqa: ARG001
):
    """Leere oder Whitespace-only URLs werden ignoriert."""
    from tools.api_security.gui.api_security_widget import ApiSecurityWidget

    widget = ApiSecurityWidget()
    qtbot.add_widget(widget)
    widget._url_input.setText("vorbestand")  # noqa: SLF001
    widget.apply_navigation(url="   ")
    assert widget._url_input.text() == "vorbestand"  # noqa: SLF001


def test_api_security_apply_navigation_ohne_url_kein_crash(qtbot, app):  # noqa: ARG001
    """Andere kwargs werden ignoriert (forward-kompatibel)."""
    from tools.api_security.gui.api_security_widget import ApiSecurityWidget

    widget = ApiSecurityWidget()
    qtbot.add_widget(widget)
    widget._url_input.setText("vor")  # noqa: SLF001
    widget.apply_navigation(domain="x.de")  # url fehlt
    assert widget._url_input.text() == "vor"  # noqa: SLF001


# ---------------------------------------------------------------------------
# cert_monitor.apply_navigation(domain=...)
# ---------------------------------------------------------------------------


def test_cert_monitor_apply_navigation_setzt_domain(qtbot, app):  # noqa: ARG001
    from tools.cert_monitor.application.cert_monitor_service import (
        CertMonitorService,
    )
    from tools.cert_monitor.gui.cert_monitor_widget import CertMonitorWidget

    service = MagicMock(spec=CertMonitorService)
    service.lade_letzte_ergebnisse.return_value = []
    widget = CertMonitorWidget(service)
    qtbot.add_widget(widget)
    widget.apply_navigation(domain="example.com")
    assert widget._domain_input.text() == "example.com"  # noqa: SLF001


# ---------------------------------------------------------------------------
# network_scanner.apply_navigation(target=...)
# ---------------------------------------------------------------------------


def test_network_scanner_apply_navigation_setzt_target(qtbot, app):  # noqa: ARG001
    from tools.network_scanner.application.network_service import NetworkService

    service = MagicMock(spec=NetworkService)
    # NetworkScannerWidget.__init__ befüllt die Felder via eigene_netzwerk_info;
    # der Daten-Layer liefert dort vertraglich ("", "", "") — der Mock muss das
    # Drei-Tupel explizit setzen, sonst scheitert das Entpacken.
    service.eigene_netzwerk_info.return_value = ("", "", "")
    widget = NetworkScannerWidget(service)
    qtbot.add_widget(widget)
    widget.apply_navigation(target="192.0.2.5")
    assert widget._ziel_input.text() == "192.0.2.5"  # noqa: SLF001


# ---------------------------------------------------------------------------
# network_scanner._build_url
# ---------------------------------------------------------------------------


def test_build_url_https_default_port():
    """https + Port 443 → ohne ``:443``-Suffix."""
    assert (
        NetworkScannerWidget._build_url("https", "example.com", 443)
        == "https://example.com"
    )


def test_build_url_http_default_port():
    """http + Port 80 → ohne ``:80``-Suffix."""
    assert (
        NetworkScannerWidget._build_url("http", "example.com", 80)
        == "http://example.com"
    )


def test_build_url_alternative_port_inkludiert_port():
    """Andere Ports landen mit ``:port``-Suffix."""
    assert (
        NetworkScannerWidget._build_url("https", "example.com", 8443)
        == "https://example.com:8443"
    )
    assert (
        NetworkScannerWidget._build_url("http", "example.com", 8080)
        == "http://example.com:8080"
    )


# ---------------------------------------------------------------------------
# network_scanner Trigger: _open_api_scan / _open_cert_monitor delegieren
# ---------------------------------------------------------------------------


def test_open_api_scan_ruft_navigate_to_mit_url(qtbot, app):  # noqa: ARG001
    from tools.network_scanner.application.network_service import NetworkService

    service = MagicMock(spec=NetworkService)
    # NetworkScannerWidget.__init__ befüllt die Felder via eigene_netzwerk_info;
    # der Daten-Layer liefert dort vertraglich ("", "", "") — der Mock muss das
    # Drei-Tupel explizit setzen, sonst scheitert das Entpacken.
    service.eigene_netzwerk_info.return_value = ("", "", "")
    widget = NetworkScannerWidget(service)
    qtbot.add_widget(widget)

    fake_window = MagicMock()
    with patch.object(widget, "window", return_value=fake_window):
        widget._open_api_scan("https://example.com")  # noqa: SLF001
    fake_window.navigate_to.assert_called_once_with(
        "api_security", url="https://example.com"
    )


def test_open_cert_monitor_ruft_navigate_to_mit_domain(qtbot, app):  # noqa: ARG001
    from tools.network_scanner.application.network_service import NetworkService

    service = MagicMock(spec=NetworkService)
    # NetworkScannerWidget.__init__ befüllt die Felder via eigene_netzwerk_info;
    # der Daten-Layer liefert dort vertraglich ("", "", "") — der Mock muss das
    # Drei-Tupel explizit setzen, sonst scheitert das Entpacken.
    service.eigene_netzwerk_info.return_value = ("", "", "")
    widget = NetworkScannerWidget(service)
    qtbot.add_widget(widget)

    fake_window = MagicMock()
    with patch.object(widget, "window", return_value=fake_window):
        widget._open_cert_monitor("example.com")  # noqa: SLF001
    fake_window.navigate_to.assert_called_once_with(
        "cert_monitor", domain="example.com"
    )


def test_open_helpers_kein_crash_wenn_window_kein_navigate_to_hat(  # noqa: E501
    qtbot, app  # noqa: ARG001
):
    """Defensive: Widget ohne ``window.navigate_to`` darf nicht crashen."""
    from tools.network_scanner.application.network_service import NetworkService

    service = MagicMock(spec=NetworkService)
    # NetworkScannerWidget.__init__ befüllt die Felder via eigene_netzwerk_info;
    # der Daten-Layer liefert dort vertraglich ("", "", "") — der Mock muss das
    # Drei-Tupel explizit setzen, sonst scheitert das Entpacken.
    service.eigene_netzwerk_info.return_value = ("", "", "")
    widget = NetworkScannerWidget(service)
    qtbot.add_widget(widget)

    class _PlainWindow:
        pass

    with patch.object(widget, "window", return_value=_PlainWindow()):
        widget._open_api_scan("https://x")  # noqa: SLF001
        widget._open_cert_monitor("x")  # noqa: SLF001


# ---------------------------------------------------------------------------
# network_monitor: geteilter scan_link.navigate_to_scan Deep-Link
# ---------------------------------------------------------------------------


def test_connection_table_open_network_scan(qtbot, app):  # noqa: ARG001
    # Deep-Link laeuft jetzt ueber den geteilten scan_link-Helfer.
    from tools.network_monitor.gui.connection_table import ConnectionTable
    from tools.network_monitor.gui.scan_link import navigate_to_scan

    table = ConnectionTable()
    qtbot.add_widget(table)

    fake_window = MagicMock()
    with patch.object(table, "window", return_value=fake_window):
        navigate_to_scan(table, "192.0.2.10")
    fake_window.navigate_to.assert_called_once_with(
        "network_scanner", target="192.0.2.10"
    )


def test_connection_table_open_network_scan_kein_crash_ohne_navigate(
    qtbot, app  # noqa: ARG001
):
    from tools.network_monitor.gui.connection_table import ConnectionTable
    from tools.network_monitor.gui.scan_link import navigate_to_scan

    table = ConnectionTable()
    qtbot.add_widget(table)

    class _PlainWindow:
        pass

    with patch.object(table, "window", return_value=_PlainWindow()):
        navigate_to_scan(table, "192.0.2.99")
