"""Seiten des First-Run-Wizards.

Jede Seite ist ein:class:`QWidget` mit einem ``is_complete``-Signal.
Aktive Seiten validieren ihre Eingabe; Skelett-Seiten sind reine Info-
Platzhalter für spätere Ausbauten.
"""

from __future__ import annotations

from core.first_run_wizard.pages.admin_setup_page import AdminSetupPage
from core.first_run_wizard.pages.backup_location_page import BackupLocationPage
from core.first_run_wizard.pages.company_info_page import CompanyInfoPage
from core.first_run_wizard.pages.completion_page import CompletionPage
from core.first_run_wizard.pages.recovery_code_page import RecoveryCodeDisplayPage
from core.first_run_wizard.pages.scoping_page import CompanyScopingPage
from core.first_run_wizard.pages.two_factor_page import TwoFactorPage
from core.first_run_wizard.pages.welcome_page import WelcomePage

__all__ = [
    "AdminSetupPage",
    "BackupLocationPage",
    "CompanyInfoPage",
    "CompanyScopingPage",
    "CompletionPage",
    "RecoveryCodeDisplayPage",
    "TwoFactorPage",
    "WelcomePage",
]
