"""Patch-Monitor Status-Zeile: installierbare Update-Teilmenge ausweisen (Patrick 2026-06-29).

Behebt die Wahrnehmung „11 Updates verfuegbar, aber nur 2-3 auswaehlbar": Registry-/
MSIX-Apps ohne winget-/Store-Eintrag zaehlen als Update, sind aber nicht ankreuzbar/
batch-installierbar. Die Status-Zeile weist die installierbare Teilmenge jetzt aus.
"""

from __future__ import annotations

from tools.patch_monitor.gui.patch_console_widget import _format_status_line


class _R:
    """Duck-typed PatchScanResult (Status-Zeile nutzt nur diese Felder)."""

    def __init__(
        self,
        recommendation: str,
        *,
        winget_id: str | None = None,
        store_id: str | None = None,
        is_update_available: bool | None = None,
    ) -> None:
        self.recommendation = recommendation
        self.winget_id = winget_id
        self.store_id = store_id
        # „Updates verfuegbar" zaehlt jetzt is_update_available (roh) statt der
        # recommendation-Klasse. Default aus der Recommendation ableiten, damit
        # bestehende Faelle ihre Intent behalten; per Param ueberschreibbar
        # (z. B. notify_only-App MIT verfuegbarem Update).
        self.is_update_available = (
            recommendation in ("update", "update_urgent", "update_available")
            if is_update_available is None
            else is_update_available
        )


def test_diskrepanz_zeigt_installierbare_teilmenge() -> None:
    results = [
        _R("update", winget_id="A.A"),        # installierbar
        _R("update", winget_id=None),          # Registry-only -> nicht ankreuzbar
        _R("update_urgent", winget_id=None),   # nicht ankreuzbar
        _R("up_to_date"),                      # kein Update
    ]
    line = _format_status_line(results)
    assert "3 Updates verfuegbar" in line
    assert "1 automatisch installierbar" in line


def test_store_app_zaehlt_als_installierbar() -> None:
    results = [_R("update", store_id="9WZXYZ")]  # Microsoft Store -> installierbar
    line = _format_status_line(results)
    assert "1 Updates verfuegbar" in line
    assert "installierbar" not in line  # keine Diskrepanz -> kein Zusatz


def test_keine_diskrepanz_kein_zusatz() -> None:
    results = [_R("update", winget_id="A.A"), _R("up_to_date")]
    line = _format_status_line(results)
    assert "1 Updates verfuegbar" in line
    assert "installierbar" not in line


def test_source_label_herkunft() -> None:
    from tools.patch_monitor.gui.patch_console_widget import _source_label

    assert _source_label("windows_update") == "Windows-Update"
    assert _source_label("registry") == "Registry"
    assert _source_label("winget") == "winget"
    assert _source_label("msix") == "Store/MSIX"
    assert _source_label("unbekannt") == "unbekannt"  # Fallback bei unbek. Quelle
