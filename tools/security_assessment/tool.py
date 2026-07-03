"""tool — SecurityAssessmentTool Plugin-Definition.

Registriert den verschmolzenen Bereich „Security-Bewertung" als EINEN Eintrag
in der NoRisk-ToolRegistry. Löst die vier zuvor getrennten Sidebar-Einträge
``customer_audit`` / ``security_scoring`` / ``awareness_tracker`` /
``nis2_incidents`` ab (Refactoring-Plan §4/§8, Fortschreibung von).

Composition-Root des Containers: Die Tab-Factories delegieren an die bereits
vorhandenen ``create_widget`` der vier Sub-Tools (DRY — identische Service-/
Repository-Verdrahtung), sodass die GUI-Schicht keine ``data``-Module
importiert (Hexagonal-Contract gui↛data). Die Sub-Tools bleiben eigenständige,
registrierte Module (PyInstaller-Spec + Factory-Import); sie haben nach
nur keinen eigenen Sidebar-Eintrag / kein eigenes Dock mehr.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from core.base_tool import BaseTool


def _make_audit(parent: QWidget | None) -> QWidget:
    """Baut das Security-Audit-Widget via bestehende Komposition."""
    from tools.customer_audit.tool import CustomerAuditTool  # noqa: PLC0415

    return CustomerAuditTool().create_widget(parent)


def _make_score(parent: QWidget | None) -> QWidget:
    """Baut das Security-Score-Widget via bestehende Komposition."""
    from tools.security_scoring.tool import SecurityScoringTool  # noqa: PLC0415

    return SecurityScoringTool().create_widget(parent)


def _make_awareness(parent: QWidget | None) -> QWidget:
    """Baut das Awareness-Tracker-Widget via bestehende Komposition."""
    from tools.awareness_tracker.tool import AwarenessTrackerTool  # noqa: PLC0415

    return AwarenessTrackerTool().create_widget(parent)


def _make_nis2(parent: QWidget | None) -> QWidget:
    """Baut das NIS2-Vorfälle-Widget via bestehende Komposition."""
    from tools.nis2_incidents.tool import Nis2IncidentsTool  # noqa: PLC0415

    return Nis2IncidentsTool().create_widget(parent)


def _build_tab_specs() -> list:
    """Baut die Tab-Definitionen für das Container-Widget.

    Reihenfolge nach Patrick-Wunsch: Security-Audit,
    Security-Score, Awareness-Tracker, NIS2-Vorfälle.

    Returns:
        Liste von ``(deeplink_key, license_feature, tool_name, tab_title,
        factory)``-Tupeln in Anzeige-Reihenfolge.
    """
    return [
        ("audit", "customer_audit", "Security-Audit", "Security-Audit", _make_audit),
        (
            "score",
            "security_scoring",
            "Security-Score",
            "Security-Score",
            _make_score,
        ),
        (
            "awareness",
            "awareness_tracker",
            "Awareness-Tracker",
            "Awareness-Tracker",
            _make_awareness,
        ),
        # NIS2 teilt das Lizenz-Feature ``customer_audit`` (wie der Standalone).
        ("nis2", "customer_audit", "NIS2-Vorfälle", "NIS2-Vorfälle", _make_nis2),
    ]


class SecurityAssessmentTool(BaseTool):
    """Plugin-Definition für den Bereich „Security-Bewertung".

    Attributes:
        name (str): ``"Security-Bewertung"`` — muss zum ``_NAV_TOOL_MAP``-
            Eintrag passen (Routing über den Tool-Namen).
        icon (str): Material-Symbol ``"assignment"``.
        feature_name (str): Leer — der Container ist immer sichtbar; die
            einzelnen Sub-Tabs tragen ihr bisheriges Lizenz-Feature
            (``customer_audit`` / ``security_scoring`` / ``awareness_tracker``;
            seit/Single-Tenant inert). So bleibt das Lizenzmodell
            unverändert (kein neues Feature, kein License-Server-Change).
    """

    name = "Security-Bewertung"
    icon = "assignment"
    feature_name = ""

    def create_widget(self, parent=None):
        """Baut das Container-Widget mit den vier Bewerten-Sub-Tabs.

        Args:
            parent: Optionales Eltern-Widget.

        Returns:
            SecurityAssessmentWidget-Instanz.
        """
        from tools.security_assessment.gui.security_assessment_widget import (  # noqa: PLC0415
            SecurityAssessmentWidget,
        )

        widget = SecurityAssessmentWidget(tab_specs=_build_tab_specs(), parent=parent)
        widget.setMinimumSize(900, 620)
        return widget
