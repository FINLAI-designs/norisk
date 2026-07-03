"""file_scanner — Container-Tool, das E-Mail-Anhang-, PDF-Risiko- und
Dokument-Scanner in EINEM Sidebar-Eintrag mit Sub-Tabs verschmilzt
(Refactoring-Plan §4/§8 Phase 3b).

Die drei Backends (Service + Widget) bleiben unverändert in ihren
bestehenden Paketen ``tools.email_scanner`` / ``tools.pdf_risk_scanner`` /
``tools.document_scanner``; dieses Paket enthält nur die Komposition.
"""
