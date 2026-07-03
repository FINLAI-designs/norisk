"""
severity_helpers — Severity-Farbcodierung + Lokalisierung fuer CSAF Advisory-Monitor.

Sprint 6 Phase 1: Aus core/sidebar God-File-Refactor-Pattern
auf csaf_advisor uebertragen. Diese Datei haelt nur die Severity-Mapping-
Tabellen + zwei reine Funktionen — leicht testbar, keine PySide6-
Abhaengigkeit ausser ueber den theme-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core import theme

# ---------------------------------------------------------------------------
# Severity-Farben (Signal-Farben — semantisch, nicht im Theme)
# ---------------------------------------------------------------------------

_SEV_COLORS: dict[str, str] = {
    "critical": theme.SEVERITY_DEEP_CRITICAL,
    "high": theme.SEVERITY_DEEP_HIGH,
    "medium": theme.SEVERITY_DEEP_MEDIUM,
    "low": theme.SEVERITY_DEEP_LOW,
}

_SEV_LABELS: dict[str, str] = {
    "critical": "KRITISCH",
    "high": "HOCH",
    "medium": "MITTEL",
    "low": "NIEDRIG",
}


def sev_color(severity: str) -> str:
    """Gibt die Signalfarbe für einen Schweregrad zurück.

    Args:
        severity: Schweregrad-String.

    Returns:
        Hex-Farbstring.
    """
    return _SEV_COLORS.get(severity.lower(), theme.SEVERITY_SIGNAL_INFO)


def sev_label(severity: str) -> str:
    """Gibt den deutschen Label-Text für einen Schweregrad zurück.

    Args:
        severity: Schweregrad-String.

    Returns:
        Lokalisierter Label-Text.
    """
    return _SEV_LABELS.get(severity.lower(), severity.upper())
