"""test_bewerten_group_ia — 6-Bereiche-IA, Phase 3, 2026-06-06).

Loest die-Interim-IA ab (Audits→Bewerten-Rename). Lockt die
Workflow-orientierte 6-Bereiche-Struktur ein (Refactoring-Plan §4):

- Genau 5 statische Bereiche (Cockpit/Lage/Prüfen/Überwachen/Bewerten), in
  beiden Configs (``sidebar_config`` + ``app_config``) konsistent.
, 2026-06-13: „Assistenz"/Security-Chat entfernt, vorher 6.)
-: Reihenfolge + Anzeigenamen umgebaut (interne Keys stabil):
  cockpit · lage · ``bewerten`` („Sicherheit & Audit") · ``ueberwachen``
  („Überwachung") · ``pruefen`` („Scanner").
- ``bewerten`` = Container „Security-Bewertung" (``security_assessment``) +
  „System Optimierung" (``system_tuner``).
- Dependency-Auditor bleibt in ``pruefen`` (jetzt „Scanner").
- ``sidebar_config.items`` und ``app_config.tool_keys`` bleiben konsistent
  (Schnittmengen-Filter in ``core.sidebar._build_group_from_config``).

Bezug: Refactoring-Plan §4.
"""

from __future__ import annotations

from apps.app_config import NORISK_CONFIG

from core.sidebar_config import (
    ALL_NORISK_GROUP_CONFIGS,
    BEWERTEN_GROUP_CONFIG,
    PRUEFEN_GROUP_CONFIG,
    UEBERWACHEN_GROUP_CONFIG,
)

# Reihenfolge cockpit · lage · bewerten · ueberwachen · pruefen
# (interne Keys stabil; Anzeigenamen „Sicherheit & Audit"/„Überwachung"/„Scanner").
_EXPECTED_BEREICHE: list[str] = [
    "cockpit",
    "lage",
    "bewerten",
    "ueberwachen",
    "pruefen",
]


def _group(key: str) -> dict | None:
    return next(
        (g for g in NORISK_CONFIG.sidebar_groups if g["key"] == key), None
    )


def test_bereiche_in_beiden_configs() -> None:
    """Genau die 5 erwarteten Bereiche, gleiche Reihenfolge in beiden Configs
: „Assistenz" entfernt, vorher 6)."""
    assert [g.key for g in ALL_NORISK_GROUP_CONFIGS] == _EXPECTED_BEREICHE
    # app_config: 5 Bereiche + dynamische "links"-Gruppe am Ende.
    static_keys = [
        g["key"] for g in NORISK_CONFIG.sidebar_groups if g["key"] != "links"
    ]
    assert static_keys == _EXPECTED_BEREICHE


def test_bewerten_gruppe_label() -> None:
    """: Anzeige-Label „Sicherheit & Audit" in beiden Configs (key bleibt
    intern ``bewerten``)."""
    assert BEWERTEN_GROUP_CONFIG.key == "bewerten"
    assert BEWERTEN_GROUP_CONFIG.label == "Sicherheit & Audit"
    grp = _group("bewerten")
    assert grp is not None
    assert grp["name"] == "Sicherheit & Audit"


def test_bewerten_enthaelt_security_assessment_container() -> None:
    """Bereich „Sicherheit & Audit" (key ``bewerten``): Container
    „Security-Bewertung" (security_assessment; Audit/NIS2/Score/Awareness als
    Sub-Tabs) + „System Optimierung" (system_tuner). Tech-Stack zog in den
    Advisory-Monitor."""
    assert [i.key for i in BEWERTEN_GROUP_CONFIG.items] == [
        "security_assessment",
        "system_tuner",
    ]


def test_security_bewertung_container_hat_vier_subtabs_in_reihenfolge() -> None:
    """: Der Container exponiert die vier Bewerten-Tools als Sub-Tabs in
    der Reihenfolge Audit · Score · Awareness · NIS2 (Patrick 2026-06-29)."""
    from tools.security_assessment.tool import _build_tab_specs

    specs = _build_tab_specs()
    assert [spec[0] for spec in specs] == ["audit", "score", "awareness", "nis2"]
    assert [spec[3] for spec in specs] == [
        "Security-Audit",
        "Security-Score",
        "Awareness-Tracker",
        "NIS2-Vorfälle",
    ]


def test_awareness_ist_subtab_nicht_sidebar_item() -> None:
    """: Awareness-Tracker ist ein Sub-Tab des Bewerten-Containers — kein
    eigener Sidebar-Eintrag mehr (weder in Bewerten noch in Ueberwachen)."""
    from tools.security_assessment.tool import _build_tab_specs

    assert "awareness" in [spec[0] for spec in _build_tab_specs()]
    assert "awareness_tracker" not in [i.key for i in BEWERTEN_GROUP_CONFIG.items]
    assert "awareness_tracker" not in [
        i.key for i in UEBERWACHEN_GROUP_CONFIG.items
    ]


def test_dependency_auditor_in_pruefen() -> None:
    """Dependency-Auditor ist profil-optional unter „Prüfen" (Plan §4)."""
    assert "dependency_auditor" in [i.key for i in PRUEFEN_GROUP_CONFIG.items]
    grp = _group("pruefen")
    assert grp is not None
    assert "dependency_auditor" in grp["tool_keys"]


def test_alle_gruppen_filter_und_items_konsistent() -> None:
    """Schnittmengen-Logik: jeder gerenderte Item-Key muss im tool_keys-Filter
    der gleichnamigen app_config-Gruppe stehen — sonst verschwindet das Item
    still (Bestandsbug-Schutz, gilt fuer alle 5 Bereiche)."""
    for cfg in ALL_NORISK_GROUP_CONFIGS:
        grp = _group(cfg.key)
        assert grp is not None, f"Gruppe '{cfg.key}' fehlt in app_config"
        allowed = set(grp["tool_keys"])
        for item in cfg.items:
            assert item.key in allowed, (
                f"{item.key} fehlt im '{cfg.key}'-tool_keys-Filter → "
                f"wuerde nicht rendern"
            )
