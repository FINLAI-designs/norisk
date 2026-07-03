"""test_file_scanner_tool — Datei-Scanner-Merge, Phase 3b).

Lockt die Verschmelzung von E-Mail-Anhang-, PDF-Risiko- und Dokument-Scanner
zu EINEM Container-Tool mit Sub-Tabs ein (Refactoring-Plan §4/§8):

- FileScannerTool ist registriert (tool_modules + _NAV_TOOL_MAP) und löst die
  drei Einzel-Einträge ab.
- SidebarItem ``file_scanner`` liegt im Prüfen-Bereich; die drei alten Keys
  sind aus den Sidebar-tool_keys verschwunden.
- Deeplink-Contract akzeptiert ``tab`` für den Sub-Tab-Einstieg.
- apply_navigation(tab=...) schaltet den korrekten Sub-Tab.
"""

from __future__ import annotations

import pytest
from apps.app_config import NORISK_CONFIG
from PySide6.QtWidgets import QWidget

from core.base_tool import BaseTool
from core.deeplink_registry import accepted_kwargs
from core.main_window import MainWindow
from core.sidebar_config import PRUEFEN_GROUP_CONFIG


def test_file_scanner_tool_ist_basetool() -> None:
    """FileScannerTool ist eine BaseTool-Subklasse mit Namen 'Datei-Scanner'."""
    from tools.file_scanner.tool import FileScannerTool  # noqa: PLC0415

    assert issubclass(FileScannerTool, BaseTool)
    assert FileScannerTool.name == "Datei-Scanner"
    # Container immer sichtbar — Gating je Sub-Tab im Widget.
    assert FileScannerTool.feature_name == ""


def test_file_scanner_in_tool_modules() -> None:
    """Der verschmolzene Container ersetzt die drei Einzel-Module."""
    assert "tools.file_scanner.tool" in NORISK_CONFIG.tool_modules
    for alt in (
        "tools.email_scanner.tool",
        "tools.pdf_risk_scanner.tool",
        "tools.document_scanner.tool",
    ):
        assert alt not in NORISK_CONFIG.tool_modules


def test_file_scanner_in_nav_tool_map() -> None:
    """file_scanner hat genau einen _NAV_TOOL_MAP-Eintrag (tool_name passt zum
    FileScannerTool.name); die drei alten nav_keys sind weg."""
    entries = {nav_key: tool_name for nav_key, tool_name, *_ in MainWindow._NAV_TOOL_MAP}  # noqa: SLF001
    assert entries.get("file_scanner") == "Datei-Scanner"
    for alt in ("email_scanner", "pdf_risk_scanner", "document_scanner"):
        assert alt not in entries


def test_file_scanner_sidebar_item_in_pruefen() -> None:
    """SidebarItem file_scanner liegt im Prüfen-Bereich; alte Items sind weg."""
    keys = [i.key for i in PRUEFEN_GROUP_CONFIG.items]
    assert "file_scanner" in keys
    assert "email_scanner" not in keys
    assert "pdf_risk_scanner" not in keys

    pruefen = next(g for g in NORISK_CONFIG.sidebar_groups if g["key"] == "pruefen")
    assert "file_scanner" in pruefen["tool_keys"]
    assert "email_scanner" not in pruefen["tool_keys"]
    assert "pdf_risk_scanner" not in pruefen["tool_keys"]


def test_file_scanner_deeplink_akzeptiert_tab() -> None:
    """Deeplink-Contract: navigate_to('file_scanner', tab='pdf') ist gültig."""
    assert accepted_kwargs("file_scanner") == {"tab": str}


@pytest.mark.gui
def test_apply_navigation_schaltet_sub_tab(qtbot) -> None:
    """apply_navigation(tab=...) wählt den korrekten Sub-Tab; unbekannte Werte
    ändern nichts. Robust gegen Lizenz-/Backend-Zustand (immer 3 Tabs)."""
    from tools.file_scanner.tool import FileScannerTool  # noqa: PLC0415

    # Über den Composition-Root bauen (reale Tab-Factories + Deeplink-Keys).
    widget = FileScannerTool().create_widget()
    qtbot.addWidget(widget)

    assert widget._tabs.count() == 3  # noqa: SLF001

    widget.apply_navigation(tab="pdf")
    assert widget._tabs.currentIndex() == 1  # noqa: SLF001
    widget.apply_navigation(tab="office")
    assert widget._tabs.currentIndex() == 2  # noqa: SLF001
    widget.apply_navigation(tab="email")
    assert widget._tabs.currentIndex() == 0  # noqa: SLF001

    # Unbekannter Tab → kein Wechsel
    widget.apply_navigation(tab="gibtsnicht")
    assert widget._tabs.currentIndex() == 0  # noqa: SLF001


@pytest.mark.gui
def test_ladefehler_zeigt_fehler_statt_lizenz_placeholder(qtbot, monkeypatch) -> None:
    """Ein lizenzierter, aber nicht ladbarer Sub-Scanner zeigt eine LADE-Fehler-
    Meldung — nicht fälschlich den Lizenz-Platzhalter P3-Folgefix)."""
    from PySide6.QtWidgets import QLabel  # noqa: PLC0415

    from tools.file_scanner.gui import file_scanner_widget as fsw  # noqa: PLC0415

    # Die Factory wirft beim Aufbau (kein Lizenz-Gate mehr).
    def _factory_boom(_parent: object) -> object:
        raise RuntimeError("Backend nicht verfügbar")

    spec = (
        "email", "email_attachment_scanner", "E-Mail-Anhang", "E-Mail", _factory_boom,
    )
    widget = fsw.FileScannerWidget([spec])
    qtbot.addWidget(widget)

    text = "\n".join(lbl.text() for lbl in widget.findChildren(QLabel))
    assert "geladen" in text  # Lade-Fehler-Meldung
    assert "Lizenz" not in text  # NICHT die Lizenz-Meldung


# ---------------------------------------------------------------------------
# shutdown — Sub-Teardown-Durchreichung
# ---------------------------------------------------------------------------


class _RecordingSub(QWidget):
    """Fake-Sub-Widget, das shutdown-Aufrufe protokolliert (optional wirft)."""

    def __init__(self, calls: list[str], name: str, *, boom: bool = False) -> None:
        super().__init__()
        self._calls = calls
        self._name = name
        self._boom = boom

    def shutdown(self) -> None:
        self._calls.append(self._name)
        if self._boom:
            raise RuntimeError(f"shutdown {self._name} boom")


def _spec(deeplink: str, factory) -> tuple:  # noqa: ANN001
    return (deeplink, f"feat_{deeplink}", deeplink.upper(), deeplink, factory)


@pytest.mark.gui
def test_shutdown_reicht_an_sub_widgets_durch(qtbot, monkeypatch) -> None:
    """shutdown ruft duck-typed sub.shutdown je Tab; Tabs ohne shutdown
    (z. B. Platzhalter/E-Mail-Scanner) werden übersprungen."""
    from tools.file_scanner.gui import file_scanner_widget as fsw  # noqa: PLC0415

    calls: list[str] = []
    specs = [
        _spec("email", lambda _p: _RecordingSub(calls, "email")),
        _spec("pdf", lambda _p: QWidget()),  # kein shutdown -> übersprungen
        _spec("office", lambda _p: _RecordingSub(calls, "office")),
    ]
    widget = fsw.FileScannerWidget(specs)
    qtbot.addWidget(widget)

    widget.shutdown()
    assert calls == ["email", "office"]


@pytest.mark.gui
def test_shutdown_ist_idempotent(qtbot, monkeypatch) -> None:
    """Ein zweiter shutdown-Aufruf ist ein No-op (closeEvent kann mehrfach
    feuern) — kein doppelter Sub-Teardown."""
    from tools.file_scanner.gui import file_scanner_widget as fsw  # noqa: PLC0415

    calls: list[str] = []
    widget = fsw.FileScannerWidget(
        [_spec("office", lambda _p: _RecordingSub(calls, "office"))]
    )
    qtbot.addWidget(widget)

    widget.shutdown()
    widget.shutdown()
    assert calls == ["office"]


@pytest.mark.gui
def test_shutdown_ueberlebt_sub_exception(qtbot, monkeypatch) -> None:
    """Eine Exception in einem Sub-shutdown bricht den Teardown der übrigen
    nicht ab (Shutdown-Boundary)."""
    from tools.file_scanner.gui import file_scanner_widget as fsw  # noqa: PLC0415

    calls: list[str] = []
    specs = [
        _spec("email", lambda _p: _RecordingSub(calls, "email", boom=True)),
        _spec("office", lambda _p: _RecordingSub(calls, "office")),
    ]
    widget = fsw.FileScannerWidget(specs)
    qtbot.addWidget(widget)

    widget.shutdown()  # darf nicht propagieren
    assert calls == ["email", "office"]  # office trotz email-Boom geräumt
