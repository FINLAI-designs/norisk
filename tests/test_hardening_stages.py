"""
test_hardening_stages — pytest-Tests fuer
``tools.security_scoring.domain.hardening_stages``.

Phase 1.3 des Hardening-Score-Sprints. Pure Logik, keine I/O.

Test-Bereiche:
    * ScoreStage-Dataclass: contains, frozen + hashable.
    * SCORE_STAGES-Definition: 4 Stages, lueckenlos 0-100, korrekte
      Color-Keys.
    * score_to_stage: Schwellen-Verhalten (85/65/40), Float-Rundung,
      Clamping ausserhalb [0, 100].
    * validate_stages_cover_full_range: Modul-Lade-Invariante.
    * Theme-Integration: Color-Keys passen zu
      ``core.theme.SCORE_STAGE_COLORS``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest

from core import theme
from tools.security_scoring.domain.hardening_stages import (
    SCORE_STAGES,
    ScoreStage,
    score_to_stage,
    validate_stages_cover_full_range,
)

# ===========================================================================
# ScoreStage Dataclass
# ===========================================================================


class TestScoreStageDataclass:
    """Frozen + slots + Domain-Methode contains."""

    def test_is_frozen(self):
        stage = ScoreStage(label="Test", color_key="x", min_score=0, max_score=10)
        with pytest.raises(Exception):  # noqa: B017, BLE001 — FrozenInstanceError
            stage.label = "Andere"  # type: ignore[misc]

    def test_is_hashable(self):
        # frozen=True + slots=True macht hashable
        a = ScoreStage("A", "k", 0, 10)
        b = ScoreStage("A", "k", 0, 10)
        assert hash(a) == hash(b)
        assert {a, b} == {a}  # Set-Member-Test

    def test_contains_inclusive_boundaries(self):
        stage = ScoreStage("X", "x", 40, 64)
        assert stage.contains(40)
        assert stage.contains(64)
        assert stage.contains(50)
        assert not stage.contains(39)
        assert not stage.contains(65)


# ===========================================================================
# SCORE_STAGES Definition v2 §3)
# ===========================================================================


class TestScoreStagesDefinition:
    """Stages-Datenstruktur erfuellt den-Vertrag."""

    def test_exactly_four_stages(self):
        assert len(SCORE_STAGES) == 4

    def test_labels_match_adr_008(self):
        labels = [s.label for s in SCORE_STAGES]
        assert labels == ["Secure", "Moderate", "At Risk", "Critical"]

    def test_color_keys_match_theme(self):
        # Color-Keys muessen in core.theme.SCORE_STAGE_COLORS aufgeloest werden
        for stage in SCORE_STAGES:
            assert stage.color_key in theme.SCORE_STAGE_COLORS, (
                f"ScoreStage-color_key {stage.color_key!r} fehlt in "
                "theme.SCORE_STAGE_COLORS"
            )

    def test_schwellen_pro_stage(self):
        # v2 §3: 85/65/40-Schwellen
        secure = SCORE_STAGES[0]
        assert (secure.min_score, secure.max_score) == (85, 100)

        moderate = SCORE_STAGES[1]
        assert (moderate.min_score, moderate.max_score) == (65, 84)

        at_risk = SCORE_STAGES[2]
        assert (at_risk.min_score, at_risk.max_score) == (40, 64)

        critical = SCORE_STAGES[3]
        assert (critical.min_score, critical.max_score) == (0, 39)


# ===========================================================================
# score_to_stage — Schwellen-Verhalten
# ===========================================================================


class TestScoreToStageThresholds:
    """Exakte Schwellen-Werte sind erwartet zu Standard-Stages."""

    @pytest.mark.parametrize(
        ("score", "expected_label"),
        [
            (0,   "Critical"),
            (39,  "Critical"),
            (40,  "At Risk"),
            (64,  "At Risk"),
            (65,  "Moderate"),
            (84,  "Moderate"),
            (85,  "Secure"),
            (100, "Secure"),
        ],
    )
    def test_boundary_scores_map_to_expected_stage(self, score, expected_label):
        stage = score_to_stage(score)
        assert stage.label == expected_label

    @pytest.mark.parametrize(
        ("score", "expected_label"),
        [
            (10,  "Critical"),
            (50,  "At Risk"),
            (75,  "Moderate"),
            (95,  "Secure"),
        ],
    )
    def test_typical_scores_map_correctly(self, score, expected_label):
        assert score_to_stage(score).label == expected_label


class TestScoreToStageFloats:
    """Float-Inputs werden auf int gerundet."""

    def test_84_5_rounds_up_to_secure(self):
        # 84.5 → round(84.5) = 84 (Banker's-Rounding!) → Moderate
        # Python verwendet Banker's-Rounding (round-half-to-even).
        # Wir testen primaer den Fakt, dass int(round) verwendet wird.
        result = score_to_stage(84.5)
        # 84.5 → 84 (round-to-even) → Moderate
        assert result.label == "Moderate"

    def test_84_6_rounds_to_secure(self):
        # 84.6 → 85 → Secure (klare Aufrundung)
        assert score_to_stage(84.6).label == "Secure"

    def test_84_4_rounds_to_moderate(self):
        # 84.4 → 84 → Moderate
        assert score_to_stage(84.4).label == "Moderate"

    def test_zero_point_five(self):
        # 0.5 → 0 (banker's-rounding) → Critical
        assert score_to_stage(0.5).label == "Critical"

    def test_exact_85_float(self):
        assert score_to_stage(85.0).label == "Secure"


class TestScoreToStageClamping:
    """Werte ausserhalb [0, 100] werden geclampt."""

    def test_negative_score_clamps_to_critical(self):
        assert score_to_stage(-5).label == "Critical"

    def test_score_over_100_clamps_to_secure(self):
        assert score_to_stage(150).label == "Secure"
        assert score_to_stage(101).label == "Secure"


# ===========================================================================
# validate_stages_cover_full_range
# ===========================================================================


class TestValidateStagesInvariant:
    """Stages decken 0-100 lueckenlos ab — Modul-Lade-Invariante."""

    def test_real_stages_pass_validation(self):
        # Bei korrekt geladenem Modul kein AssertionError
        validate_stages_cover_full_range()


# ===========================================================================
# Theme-Integration
# ===========================================================================


class TestThemeIntegration:
    """SCORE_STAGE_COLORS-Keys sind alle 4 Stage-color_keys vorhanden."""

    def test_all_color_keys_resolvable(self):
        for stage in SCORE_STAGES:
            hex_color = theme.SCORE_STAGE_COLORS.get(stage.color_key)
            assert hex_color is not None, (
                f"color_key {stage.color_key!r} aus Stage {stage.label!r} "
                "ist nicht in theme.SCORE_STAGE_COLORS"
            )
            # Hex-Format-Check (#RRGGBB)
            assert hex_color.startswith("#")
            assert len(hex_color) == 7

    def test_theme_dict_has_exactly_four_entries(self):
        # Wenn jemand SCORE_STAGE_COLORS um andere Keys erweitert (z. B.
        # 5. Stage), sollte das hier auffallen.
        assert len(theme.SCORE_STAGE_COLORS) == 4
