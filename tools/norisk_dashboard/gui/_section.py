"""
_section — Re-Export der Section-Komponente aus core/widgets.

 AP7: Die Implementierung lebt jetzt tool-unabhängig in
``core/widgets/section.py``. Dieser Alias hält bestehende Importe
(dashboard_widget, light_siem_section, Tests) stabil.

Author: Patrick Riederich
Version: 0.2 AP7 — Re-Export; Implementierung war v0.1)
"""

from __future__ import annotations

from core.widgets.section import Section as _DashboardSection

__all__ = ["_DashboardSection"]
