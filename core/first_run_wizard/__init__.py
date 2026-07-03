"""First-Run-Wizard für FINLAI-Apps (Beta + Pro-Launch).

Wird beim allerersten App-Start gezeigt, wenn noch kein Benutzer mit
gesetztem Passwort existiert. Legt einen Administrator an und bereitet
die Slot-Stellen für spätere Schritte (2FA, Recovery-Code, Firmendaten,
Backup-Pfad) vor.

Öffentliche API:
    needs_first_run — True, wenn Wizard gezeigt werden muss.
    run_first_run_wizard(parent) — Startet den Wizard (QDialog).
"""

from __future__ import annotations

from core.first_run_wizard.trigger import adopt_legacy_users, needs_first_run
from core.first_run_wizard.wizard import FirstRunResult, run_first_run_wizard

__all__ = [
    "FirstRunResult",
    "adopt_legacy_users",
    "needs_first_run",
    "run_first_run_wizard",
]
