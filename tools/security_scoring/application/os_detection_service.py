"""os_detection_service — Auto-Detection-Wrapper fuer Org-Security.

Stellt die OS-Detection-Funktionen aus ``data/os_detection.py`` als
application-Layer-API bereit, damit die Wizard-GUI nicht direkt aus
``data/`` importieren muss.

Schichtzugehoerigkeit: ``application/`` (Re-Export-Modul; die eigentliche
Logik bleibt in ``data/`` weil sie systemnahe Adapter sind — Registry,
PowerShell, sysctl).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.security_scoring.data.os_detection import (
    STATUS_AKTIV,
    STATUS_INAKTIV,
    STATUS_UNBEKANNT,
    PasswortManagerStatus,
    WindowsHelloStatus,
    check_installed_password_managers,
    check_windows_hello,
)

__all__ = [
    "PasswortManagerStatus",
    "STATUS_AKTIV",
    "STATUS_INAKTIV",
    "STATUS_UNBEKANNT",
    "WindowsHelloStatus",
    "check_installed_password_managers",
    "check_windows_hello",
]
