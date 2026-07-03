"""techstack — Tech-Stack Monitoring als eigenständiges Tool.

Verwaltet den persönlichen Tech-Stack für CVE-Monitoring. Zuvor Tab 4
innerhalb von:mod:`tools.cyber_dashboard`; ab 2026-04-20 als separates
Sidebar-Tool in der Gruppe "Scanner & Tools".

Die Daten (Repository, Domain-Modelle) liegen weiterhin unter
:mod:`tools.cyber_dashboard.data.techstack_repository` und werden
geteilt — das Tool ändert nur die UI-Verortung, nicht die Datenhaltung.
"""

from .tool import TechStackTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["TechStackTool"]
