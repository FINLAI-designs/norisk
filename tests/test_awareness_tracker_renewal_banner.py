"""
test_awareness_tracker_renewal_banner.

Tests fuer die *reinen* Berechnungs-Funktionen des Renewal-Banners
(``_severity``, ``_severity_icon``, ``_build_title``, ``_build_detail``).
Die QFrame-Klasse selbst ist GUI und wird hier nicht instanziiert.
"""

from __future__ import annotations

from tools.awareness_tracker.gui.renewal_banner import (
    _build_detail,
    _build_title,
    _severity,
    _severity_icon,
)


class TestSeverity:
    def test_expired_ist_critical(self) -> None:
        assert _severity(expired=1, expiring=0) == "critical"

    def test_nur_expiring_ist_warning(self) -> None:
        assert _severity(expired=0, expiring=3) == "warning"

    def test_keine_ist_ok(self) -> None:
        assert _severity(expired=0, expiring=0) == "ok"

    def test_beides_ist_critical(self) -> None:
        # Mind. 1 abgelaufen → Critical, auch wenn auch auslaufende da sind.
        assert _severity(expired=2, expiring=5) == "critical"


class TestSeverityIcon:
    def test_alle_drei_severities_haben_icon(self) -> None:
        # _severity_icon liefert (icon_name, hex_color) — Material Symbols
        # statt Emojis (R2-Compliance, Coding-Rules-Backlog 2026-05-17).
        critical_name, _ = _severity_icon("critical")
        warning_name, _ = _severity_icon("warning")
        ok_name, _ = _severity_icon("ok")
        assert critical_name == "error"
        assert warning_name == "warning"
        assert ok_name == "check_circle"

    def test_unknown_severity_fallback(self) -> None:
        # Fallback ist OK-Stufe (gruen, check_circle).
        name, _ = _severity_icon("nonsense")
        assert name == "check_circle"

    def test_severity_farbe_aus_theme(self) -> None:
        from core import theme  # noqa: PLC0415

        _, critical_color = _severity_icon("critical")
        _, warning_color = _severity_icon("warning")
        _, ok_color = _severity_icon("ok")
        assert critical_color == theme.DANGER
        assert warning_color == theme.WARNING
        assert ok_color == theme.SUCCESS


class TestBuildTitle:
    def test_alle_aktuell(self) -> None:
        title = _build_title(expired=0, expiring=0)
        assert "aktuell" in title.lower()

    def test_nur_abgelaufen(self) -> None:
        title = _build_title(expired=2, expiring=0)
        assert "abgelaufen" in title.lower()
        assert "auslaufend" not in title.lower()

    def test_nur_auslaufend(self) -> None:
        title = _build_title(expired=0, expiring=3)
        assert "auslaufen" in title.lower() or "laufen aus" in title.lower()

    def test_beides(self) -> None:
        title = _build_title(expired=1, expiring=2)
        assert "abgelaufen" in title.lower()
        assert "auslaufend" in title.lower() or "laufen aus" in title.lower()


class TestBuildDetail:
    def test_alle_aktuell_friendly(self) -> None:
        detail = _build_detail(expired=0, expiring=0)
        assert "Warn-Fensters" in detail or "innerhalb" in detail

    def test_singular_pluralisierung(self) -> None:
        d_one = _build_detail(expired=1, expiring=0)
        d_two = _build_detail(expired=2, expiring=0)
        assert "1 Schulung" in d_one
        assert "2 Schulungen" in d_two

    def test_kombiniert(self) -> None:
        detail = _build_detail(expired=2, expiring=3)
        assert "2 Schulungen abgelaufen" in detail
        assert "3 Schulungen" in detail
