"""
supply_chain_monitor — Vendor- und Dienstleister-Inventar fuer NIS2 GV.SC.

NoRisks Antwort auf die NIS2-Anforderung Art. 21(2)(d) (Supply-Chain-
Sicherheit) und das NIST-CSF-Cluster GV.SC. Das Tool baut ein
verschluesseltes Vendor-Inventar fuer Kanzleien und KMUs mit:

- Kategorisierter Vendor-DB (Kanzleisoftware / Cloud / MSP /
  Kommunikation / Spezial)
- Kritikalitaets-Score 1-5 pro Vendor (manuell + spaeter Auto-Vorschlag)
- AVV-Tracker (Pruefdatum, Renewal, Art. 28 Abs. 3 Pflichtinhalte)
- Auto-Detection ueber Installed-Apps + MX + Cert-Issuer + Outlook
- Verknuepfung mit dem Patch-Monitor (Vendor X hat Y offene CVEs)
- Export GV.SC-Compliance-Report + AVV-Status-Report

Iteration 2a: Skeleton mit Domain-Models,
Vendor-DB-Repo, manueller Add-Form und leerer GUI. Auto-Detection,
AVV-Tracker und Reports folgen in 2b-2d.

Bezug: NoRisk_AUDIT_ERWEITERUNG_KONZEPT.md §5.1, NoRisk_TASKS.md.
"""

from .tool import SupplyChainMonitorTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["SupplyChainMonitorTool"]
