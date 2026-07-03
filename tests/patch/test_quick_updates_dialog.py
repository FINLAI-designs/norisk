"""test_quick_updates_dialog — Popup „Gefundene Updates" (Live-Test 2026-07-02).

Deckt das Popup ab, das nach „Schnell nach Updates suchen" die patchbaren Apps
mit Konfig (Kanal/Strategie) + Direkt-Installation zeigt:
    * Zeilen werden aus den uebergebenen Updates aufgebaut.
    * Checkbox nur bei installierbaren Zeilen; „Alle markieren" hakt sie an.
    * Install-Button erst bei Auswahl aktiv; ``on_install`` bekommt die Auswahl.
    * Kanal-/Strategie-Aenderung persistiert ueber den Service und laedt neu
      (``on_reload``) — der Uebernahme-Pfad in den Haupt-Monitor.

Echte Qt-Widgets -> ``@pytest.mark.gui``.
"""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt

from core.patch_result import PatchScanResult
from tools.patch_monitor.gui.quick_updates_dialog import QuickUpdatesDialog

_CHANNEL_LABELS = {"latest": "Neueste", "stable": "Stabil", "notify_only": "Nur melden"}
_STRATEGY_LABELS = {"stable": "Stabil", "latest": "Neueste", "none": "Nicht patchen"}


def _result(
    name: str = "App",
    winget_id: str | None = "Vendor.App",
    recommendation: str = "update",
) -> PatchScanResult:
    return PatchScanResult(
        name=name,
        normalized_name=name.lower(),
        vendor=None,
        winget_id=winget_id,
        source="winget",
        installed_version="1.0",
        available_version="2.0",
        channel="latest",
        policy_source="policy",
        cve_ids=(),
        cvss_max=None,
        exploit_available=False,
        eol=False,
        confidence_score=0.9,
        recommendation=recommendation,
    )


class _FakeService:
    def __init__(self) -> None:
        self.channel_calls: list[tuple] = []
        self.strategy_calls: list[tuple] = []

    def set_channel_override(self, name: str, winget_id: str, channel: object) -> None:
        self.channel_calls.append((name, winget_id, channel))

    def set_strategy(self, winget_id: str, strategy: object) -> None:
        self.strategy_calls.append((winget_id, strategy))


def _make_dialog(qapp, updates, *, on_reload=None, on_install=None):  # noqa: ANN001
    service = _FakeService()
    installed: list[list[PatchScanResult]] = []

    dialog = QuickUpdatesDialog(
        updates=updates,
        channel_labels=_CHANNEL_LABELS,
        strategy_labels=_STRATEGY_LABELS,
        is_upgradeable=lambda r: bool(r.winget_id),
        source_label=lambda s: s,
        service=service,
        on_reload=on_reload or (lambda: list(updates)),
        on_install=on_install or installed.append,
        parent=None,
    )
    return dialog, service, installed


@pytest.mark.gui
class TestQuickUpdatesDialog:
    def test_zeilen_werden_aufgebaut(self, qapp) -> None:
        dialog, _svc, _inst = _make_dialog(
            qapp, [_result(name="Firefox"), _result(name="Chrome")]
        )
        assert dialog._table.rowCount() == 2

    def test_install_button_erst_bei_auswahl_aktiv(self, qapp) -> None:
        dialog, _svc, installed = _make_dialog(qapp, [_result(name="Firefox")])
        assert not dialog._install_btn.isEnabled()

        dialog._table.item(0, 0).setCheckState(Qt.CheckState.Checked)
        assert dialog._install_btn.isEnabled()

        dialog._on_install_clicked()
        assert len(installed) == 1
        assert installed[0][0].name == "Firefox"

    def test_alle_markieren(self, qapp) -> None:
        dialog, _svc, _inst = _make_dialog(
            qapp, [_result(name="A"), _result(name="B")]
        )
        dialog._select_all()
        assert len(dialog._selected_results()) == 2

    def test_nicht_installierbare_zeile_ohne_checkbox(self, qapp) -> None:
        # Ohne winget_id ist die Zeile nicht direkt installierbar.
        dialog, _svc, _inst = _make_dialog(qapp, [_result(name="RegApp", winget_id=None)])
        check = dialog._table.item(0, 0)
        assert not (check.flags() & Qt.ItemFlag.ItemIsUserCheckable)

    def test_channel_aenderung_persistiert_und_laedt_neu(self, qapp) -> None:
        reloaded: list[bool] = []
        dialog, service, _inst = _make_dialog(
            qapp,
            [_result(name="Firefox")],
            on_reload=lambda: reloaded.append(True) or [_result(name="Firefox")],
        )
        dialog._on_channel_changed("Firefox", "Vendor.App", "stable")
        assert service.channel_calls == [("Firefox", "Vendor.App", "stable")]
        # Reload laeuft verzoegert (QTimer) — hier direkt aufrufen.
        dialog._reload()
        assert reloaded == [True]

    def test_auswahl_ueberlebt_reload(self, qapp) -> None:
        # Live-Test-Bug 2026-07-02: Kanal-/Strategie-Aenderung darf die bereits
        # gesetzten Haekchen nicht verwerfen.
        updates = [
            _result(name="Firefox", winget_id="Mozilla.Firefox"),
            _result(name="Chrome", winget_id="Google.Chrome"),
        ]
        dialog, _svc, _inst = _make_dialog(
            qapp, updates, on_reload=lambda: list(updates)
        )
        dialog._table.item(0, 0).setCheckState(Qt.CheckState.Checked)
        assert {r.name for r in dialog._selected_results()} == {"Firefox"}

        dialog._reload()  # simuliert den Reload nach einer Konfig-Aenderung

        assert {r.name for r in dialog._selected_results()} == {"Firefox"}

    def test_itemchanged_nur_einmal_verbunden(self, qapp) -> None:
        # #15: itemChanged wird EINMAL (in _build_ui) verbunden, nicht je Reload —
        # sonst feuert _on_item_changed nach N Reloads N+1 mal.
        updates = [_result(name="Firefox")]
        dialog, _svc, _inst = _make_dialog(
            qapp, updates, on_reload=lambda: list(updates)
        )
        calls: list[int] = []
        dialog._update_count = lambda: calls.append(1)  # type: ignore[method-assign]
        dialog._reload()
        dialog._reload()
        calls.clear()  # die Reload-internen _update_count-Aufrufe ignorieren
        # Ein Toggle -> genau ein _on_item_changed -> ein _update_count.
        dialog._table.item(0, 0).setCheckState(Qt.CheckState.Checked)
        assert len(calls) == 1
