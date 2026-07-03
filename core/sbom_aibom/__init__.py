"""core.sbom_aibom — SBOM- und AI-BOM-Erzeugung fuer NoRisk.

Diese Schicht erzeugt zwei Compliance-Artefakte:

* **SBOM** (Software Bill of Materials) im CycloneDX-1.5-JSON-Format aus den
  installierten Python-Dependencies (``importlib.metadata``). Treiber: EU
  Cyber Resilience Act, NIS2, BSI.
* **AI-BOM** (AI Bill of Materials) als strukturierte Uebersicht aller
  KI-Komponenten (lokale Ollama-Modelle + externe Cloud-Dienste wie DeepL).
  Treiber: EU AI Act.

Beide Generatoren sind framework-agnostisch (kein PySide6) und werden vom
Einstellungen-Tab ``tools/einstellungen/gui/sbom_aibom_tab.py`` aufgerufen.

 (2026-05-26, autonome Session bubbly-swan).
"""

from core.sbom_aibom.ai_bom_service import AiBomService, AiComponent, build_ai_bom
from core.sbom_aibom.sbom_service import SbomComponent, SbomService, build_sbom

__all__ = [
    "AiBomService",
    "AiComponent",
    "SbomComponent",
    "SbomService",
    "build_ai_bom",
    "build_sbom",
]
