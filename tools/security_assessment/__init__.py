"""security_assessment — Bereich „Security-Bewertung".

Container-Tool, das die vier zuvor getrennten Bewerten-Tools
(Security-Audit, Security-Score, Awareness-Tracker, NIS2-Vorfälle) in EINEN
Sidebar-Eintrag mit vier Sub-Tabs verschmilzt — analog dem file_scanner-
Container. Die Sub-Tools bleiben eigenständige Module; hier werden nur ihre
``create_widget``-Factories als Tabs komponiert.
"""
