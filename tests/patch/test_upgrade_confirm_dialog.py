"""
test_upgrade_confirm_dialog — Tests fuer Stop-Step C Confirm-Dialog.

Fokus auf testbare Modul-Funktionen (``_format_request``). Echte Dialog-
Instanziierung wird unter ``@pytest.mark.gui`` separat geprueft —
fuer den No-GUI-Lauf reicht der Format-Vertrag.
"""

from __future__ import annotations

from core.patch_upgrade import UpgradeRequest
from tools.patch_monitor.gui.upgrade_confirm_dialog import _format_request


def _req(
    name: str = "Mozilla Firefox",
    version_from: str | None = "123.0",
    version_to: str | None = "124.0",
) -> UpgradeRequest:
    return UpgradeRequest(
        winget_id="Mozilla.Firefox",
        version_from=version_from,
        version_to=version_to,
        display_name=name,
    )


class TestFormatRequest:
    def test_beide_versionen_pfeil_format(self) -> None:
        text = _format_request(_req())
        assert "Mozilla Firefox" in text
        assert "123.0" in text
        assert "124.0" in text
        assert "→" in text

    def test_nur_version_to_pfeil_ohne_quelle(self) -> None:
        text = _format_request(_req(version_from=None, version_to="2.0"))
        assert "Mozilla Firefox" in text
        assert "→ 2.0" in text

    def test_ohne_versionen_nur_name(self) -> None:
        text = _format_request(_req(version_from=None, version_to=None))
        assert text == "Mozilla Firefox"

    def test_version_from_alleine_wird_als_nur_name_dargestellt(self) -> None:
        """Wenn version_to fehlt, ist die Zielversion unbekannt — keine
        irrefuehrende ``X →``-Darstellung."""
        text = _format_request(_req(version_from="1.0", version_to=None))
        assert text == "Mozilla Firefox"
