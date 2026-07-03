"""
security_scoring.tool — SecurityScoringTool Plugin-Definition.

Registriert das Security-Scoring-Dashboard in der FINLAI ToolRegistry.

Author: Patrick Riederich
Version: 1.0
"""

from core.base_tool import BaseTool
from tools.security_scoring.gui.scoring_dashboard_widget import ScoringDashboardWidget


class SecurityScoringTool(BaseTool):
    """Plugin-Definition für das Security-Scoring-Dashboard.

    Attributes:
        name (str): ``"Security-Scoring"``.
        icon (str): ``"📊"``.
        feature_name (str): ``"security_scoring"``.
    """

    name = "Security-Scoring"
    icon = "speed"
    feature_name = "security_scoring"

    def create_widget(self, parent=None) -> ScoringDashboardWidget:
        """Erstellt das ScoringDashboardWidget mit vollständigem Service-Stack.

        Baut ScoreRepository + ScannerService + NetworkService → ScoringService.

        Args:
            parent (QWidget | None, optional): Eltern-Widget.

        Returns:
            ScoringDashboardWidget: Die initialisierte Dashboard-Ansicht.
        """
        from tools.api_security.application.scanner_service import (
            ScannerService as ApiScannerService,
        )
        from tools.api_security.data.http_scanner import HttpScanner
        from tools.api_security.data.report_adapter import ReportAdapter
        from tools.api_security.data.scan_repository import (
            ScanRepository as ApiScanRepository,
        )
        from tools.network_scanner.application.network_service import NetworkService
        from tools.network_scanner.data.nmap_scanner import NmapScanner
        from tools.network_scanner.data.scan_repository import (
            ScanRepository as NetworkScanRepository,
        )
        from tools.network_scanner.data.socket_scanner import SocketScanner
        from tools.security_scoring.application.cve_exposure_service import (
            CveExposureService,
        )
        from tools.security_scoring.application.org_security_service import (
            OrgSecurityService,
        )
        from tools.security_scoring.application.scoring_service import ScoringService
        from tools.security_scoring.data.org_assessment_repository import (
            OrgAssessmentRepository,
        )
        from tools.security_scoring.data.score_repository import ScoreRepository

        api_service = ApiScannerService(
            scanner=HttpScanner(verify_ssl=True),
            reporter=ReportAdapter(),
            scan_repo=ApiScanRepository(),
        )
        network_service = NetworkService(
            scanner=SocketScanner(),
            repo=NetworkScanRepository(),
            nmap_scanner=NmapScanner(),
        )
        from core.security_subject.resolver import create_subject_store

        org_security_service = OrgSecurityService(repository=OrgAssessmentRepository())
        cve_exposure_service = CveExposureService()
        # P0-B: SubjectStore in den ScoringService injizieren, damit das
        # Mode-Gate (assert_messung_nur_self) die Subjekt-Art auflösen kann; der
        # Picker im Widget nutzt denselben Store (eigenes System + Kunden).
        subject_store = create_subject_store()
        scoring_service = ScoringService(
            score_repo=ScoreRepository(),
            api_security_service=api_service,
            network_service=network_service,
            org_security_service=org_security_service,
            cve_exposure_service=cve_exposure_service,
            subject_store=subject_store,
        )
        widget = ScoringDashboardWidget(
            service=scoring_service,
            org_security_service=org_security_service,
            subject_store=subject_store,
            parent=parent,
        )
        widget.setMinimumSize(900, 620)
        return widget
