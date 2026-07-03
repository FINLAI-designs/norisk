"""Tests für Phase D: headless BSI-Risikomatrix-PNG-Renderer."""

from __future__ import annotations

import pytest

from tools.customer_audit.application.risk_matrix_export import (
    _zone_hex,
    render_risk_matrix_png,
)
from tools.customer_audit.domain.risk_entities import RiskImpact, RiskProbability


class _A:
    """Duck-typed RiskAssessment (Renderer nutzt nur probability/impact)."""

    def __init__(self, p: int, s: int) -> None:
        self.probability = RiskProbability(p)
        self.impact = RiskImpact(s)


def test_leere_liste_kein_bild() -> None:
    assert render_risk_matrix_png([]) is None


def test_rendert_png_signatur() -> None:
    pytest.importorskip("matplotlib")  # im Build vorhanden; dev-venv ggf. ohne
    png = render_risk_matrix_png(
        [_A(4, 4), _A(1, 1), _A(2, 3), _A(4, 4)]  # u.a. zwei in derselben Zelle
    )
    assert png is not None
    assert png[:8] == b"\x89PNG\r\n\x1a\n"  # PNG-Magic
    assert len(png) > 1000  # nicht-trivial gross


def test_zonen_schwellen() -> None:
    assert _zone_hex(1) == _zone_hex(4)  # SECURE-Zone
    assert _zone_hex(5) == _zone_hex(8)  # MODERATE
    assert _zone_hex(9) == _zone_hex(12)  # AT_RISK
    assert _zone_hex(13) == _zone_hex(16)  # CRITICAL
    # vier verschiedene Zonen
    assert len({_zone_hex(2), _zone_hex(6), _zone_hex(10), _zone_hex(14)}) == 4
    # Clamp ausserhalb [1,16]
    assert _zone_hex(0) == _zone_hex(1)
    assert _zone_hex(99) == _zone_hex(16)
