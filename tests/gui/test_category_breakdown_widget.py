"""
test_category_breakdown_widget — Phase-4c Breakdown-Panel Tests.

Deckt:
    * Initial-State: alle 5 Rows "—" + Body sichtbar.
    * ``set_result(result)`` aktualisiert nur anwesende Kategorien;
      fehlende bleiben auf "—".
    * Toggle-Button kollabiert Body + emittiert ``collapsed_changed``.
    * Cap-Hinweise mit Trigger + Label (immer voll: kein Free/Pro).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from tools.security_scoring.domain.hardening_caps import HardCapEvent
from tools.security_scoring.domain.hardening_categories import (
    HardeningCategory,
)
from tools.security_scoring.domain.hardening_score import (
    CategoryScore,
    HardeningScoreResult,
)
from tools.security_scoring.domain.hardening_stages import score_to_stage
from tools.security_scoring.gui.widgets.category_breakdown_widget import (
    _CATEGORY_LABELS,
    CategoryBreakdownWidget,
)

pytestmark = pytest.mark.gui


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cscore(
    cat: HardeningCategory,
    score: float = 80.0,
    weight: float = 0.20,
    components_count: int = 2,
) -> CategoryScore:
    return CategoryScore(
        category=cat,
        score=score,
        weight=weight,
        components_count=components_count,
    )


def _result(
    *,
    overall: float = 72.0,
    raw: float | None = None,
    category_scores: tuple[CategoryScore, ...] = (),
    hard_cap_events: tuple[HardCapEvent, ...] = (),
    missing: tuple[HardeningCategory, ...] = (),
) -> HardeningScoreResult:
    return HardeningScoreResult(
        overall_score=overall,
        stage=score_to_stage(overall),
        category_scores=category_scores,
        missing_categories=missing,
        hard_cap_events=hard_cap_events,
        raw_weighted_score=overall if raw is None else raw,
    )


# ---------------------------------------------------------------------------
# Initial State
# ---------------------------------------------------------------------------


class TestInitialState:
    def test_initial_all_rows_present(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        for cat in HardeningCategory:
            row = w.category_row(cat)
            assert row.bar_value == 0
            assert row.weight_text == "—"

    def test_initial_body_visible(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        assert w.is_collapsed is False


# ---------------------------------------------------------------------------
# set_result — Rendering
# ---------------------------------------------------------------------------


class TestSetResult:
    def test_present_categories_populated(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        result = _result(
            category_scores=(
                _cscore(HardeningCategory.CVE_PATCH, score=88.0, weight=0.30),
                _cscore(HardeningCategory.NETWORK, score=72.0, weight=0.20),
            ),
            missing=(
                HardeningCategory.PASSWORD,
                HardeningCategory.API_SECURITY,
                HardeningCategory.SYSTEM_HARDENING,
            ),
        )
        w.set_result(result)

        cve_row = w.category_row(HardeningCategory.CVE_PATCH)
        assert cve_row.bar_value == 88
        assert cve_row.weight_text == "30%"

        net_row = w.category_row(HardeningCategory.NETWORK)
        assert net_row.bar_value == 72
        assert net_row.weight_text == "20%"

    def test_missing_categories_show_placeholder(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        result = _result(
            category_scores=(
                _cscore(HardeningCategory.CVE_PATCH, score=88.0),
            ),
            missing=(
                HardeningCategory.NETWORK,
                HardeningCategory.PASSWORD,
                HardeningCategory.API_SECURITY,
                HardeningCategory.SYSTEM_HARDENING,
            ),
        )
        w.set_result(result)
        missing_row = w.category_row(HardeningCategory.SYSTEM_HARDENING)
        assert missing_row.bar_value == 0
        assert missing_row.weight_text == "—"

    def test_set_result_none_resets_rows(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        w.set_result(
            _result(
                category_scores=(_cscore(HardeningCategory.NETWORK, score=70.0),)
            )
        )
        w.set_result(None)
        for cat in HardeningCategory:
            assert w.category_row(cat).bar_value == 0
            assert w.category_row(cat).weight_text == "—"

    def test_labels_match_display_mapping(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        for cat, expected_label in _CATEGORY_LABELS.items():
            assert w.category_row(cat)._label.text() == expected_label


# ---------------------------------------------------------------------------
# Collapse
# ---------------------------------------------------------------------------


class TestCollapse:
    def test_toggle_button_collapses_body(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        w.show()
        assert w.is_collapsed is False
        w._toggle_button.click()
        assert w.is_collapsed is True

    def test_collapsed_signal_fires(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        states: list[bool] = []
        w.collapsed_changed.connect(states.append)
        w.set_collapsed(True)
        w.set_collapsed(False)
        assert states == [True, False]

    def test_collapsed_no_op_when_same_state(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        states: list[bool] = []
        w.collapsed_changed.connect(states.append)
        w.set_collapsed(False)  # bereits False
        assert states == []


# ---------------------------------------------------------------------------
# Hard-Cap-Hinweise
# ---------------------------------------------------------------------------


class TestCapHints:
    def _capped_result(self) -> HardeningScoreResult:
        return _result(
            overall=50.0,
            raw=85.0,
            category_scores=(
                _cscore(HardeningCategory.SYSTEM_HARDENING, score=20.0),
            ),
            hard_cap_events=(
                HardCapEvent(
                    label="RDP ohne MFA",
                    cap_value=50,
                    triggered_by="SH-003",
                    details="RDP aktiv ohne NLA",
                ),
                HardCapEvent(
                    label="Firewall deaktiviert",
                    cap_value=60,
                    triggered_by="SH-001",
                    details="Windows-Firewall off",
                ),
            ),
        )

    def test_pro_mode_shows_all_cap_events(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        w.set_result(self._capped_result())
        texts = [lbl.text() for lbl in w.cap_hint_widgets()]
        # Summary-Zeile + 2 Event-Zeilen
        joined = " | ".join(texts)
        assert "85" in joined and "50" in joined  # Raw → Capped
        assert "SH-001" in joined
        assert "SH-003" in joined
        assert "RDP ohne MFA" in joined
        assert "Firewall deaktiviert" in joined

    def test_pro_mode_lowest_cap_first(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        w.set_result(self._capped_result())
        texts = [lbl.text() for lbl in w.cap_hint_widgets()]
        # Erste Event-Zeile (nach Summary) muss den niedrigeren Cap
        # (50, RDP) zuerst zeigen.
        event_lines = [t for t in texts if "•" in t]
        assert "SH-003" in event_lines[0]
        assert "SH-001" in event_lines[1]

    def test_no_caps_no_hint_widgets(self, app, qtbot):  # noqa: ARG002
        w = CategoryBreakdownWidget()
        qtbot.add_widget(w)
        w.set_result(
            _result(
                category_scores=(_cscore(HardeningCategory.CVE_PATCH, score=88.0),),
                hard_cap_events=(),
            )
        )
        assert w.cap_hint_widgets() == []
