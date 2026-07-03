"""
test_system_tuner_apply_terms — Apply-Nutzungshinweis (R7) + Versions-Sync.

Verifiziert, dass das Legal-Delta vorhanden, an die AGB (§ 11) verankert und
R2-konform (keine Ueber-Claims) ist und dass die Consent-Version daraus stammt.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.system_tuner.application.apply_terms import (
    APPLY_TERMS_TEXT,
    APPLY_TERMS_VERSION,
)
from tools.system_tuner.application.consent_gate import CURRENT_EULA_VERSION


def test_consent_version_is_single_sourced():
    assert CURRENT_EULA_VERSION == APPLY_TERMS_VERSION
    assert APPLY_TERMS_VERSION


def test_text_covers_required_points():
    text = APPLY_TERMS_TEXT
    assert "Administratorrechten" in text  # 1. Gegenstand
    assert "Wiederherstellungspunkt" in text  # 2. Schutz
    assert "Erforderlich" in text  # 3. Edition-Ehrlichkeit
    assert "verantwortlich" in text  # 4. Nutzer-Verantwortung
    assert "§ 11" in text  # 5. an AGB-Haftung verankert


def test_no_overclaim_wording():
    low = APPLY_TERMS_TEXT.lower()
    for tabu in (
        "dsgvo-konform",
        "telemetriefrei",
        "rechtssicher",
        "keinerlei haftung",
        "garantiert",
    ):
        assert tabu not in low, f"verbotenes Wording: {tabu}"
