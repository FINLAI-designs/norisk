"""
test_anomaly_section_text — A (Live-Test 2026-07-01).

Der Anomalie-Statustext zeigt den Baseline-Fortschritt (``Baseline X von 7
Tagen``) statt nur der Event-Zahl, damit die 5-vs-7-Verwechslung nicht
wieder auftritt. Die Text-Helfer sind pure Staticmethods — kein QApplication.

Author: Patrick Riederich
"""

from __future__ import annotations

from tools.norisk_dashboard.domain.anomaly_models import (
    MIN_BASELINE_DAYS,
    AnomalyReport,
)
from tools.norisk_dashboard.gui.anomaly_section import AnomalySection


def test_status_text_zeigt_baseline_fortschritt() -> None:
    report = AnomalyReport(total_events=5, baseline_day_count=3)
    text = AnomalySection._status_text(report)  # noqa: SLF001
    assert f"Baseline 3 von {MIN_BASELINE_DAYS} Tagen" in text
    assert "5 Ereignisse" in text


def test_empty_hint_zeigt_baseline_fortschritt() -> None:
    report = AnomalyReport(total_events=5, baseline_day_count=3)
    text = AnomalySection._empty_hint_text(report)  # noqa: SLF001
    assert f"Baseline 3 von {MIN_BASELINE_DAYS} Tagen" in text


def test_status_text_leerer_pool_unveraendert() -> None:
    report = AnomalyReport(total_events=0, baseline_day_count=0)
    text = AnomalySection._status_text(report)  # noqa: SLF001
    assert "Noch keine Ereignisse" in text
