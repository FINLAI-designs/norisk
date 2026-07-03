"""core.constants — Shim-Modul, leitet auf:mod:`core.settings` weiter.

Vor hat dieses Modul die Feature-Flags + OCR-Toggles +
Import-File-Size-Konstante direkt definiert. Mit dem R-Cfg-Sprint sind
alle Konstanten in:mod:`core.settings` (basiert auf ``pydantic-settings``)
konsolidiert. Dieses Shim erhaelt die bestehende Import-API
``from core.constants import ENABLE_LIGHT_THEME`` byte-identisch.

Schichtzugehoerigkeit: ``core/`` (framework-agnostisch).
"""

from __future__ import annotations

from core.settings import (
    ENABLE_LIGHT_THEME,
    MAX_IMPORT_FILE_SIZE,
    OCR_CHANDRA_ENABLED,
    OCR_OLLAMA_ENABLED,
    OCR_PADDLE_ENABLED,
    OCR_TESSERACT_ENABLED,
)

__all__ = [
    "ENABLE_LIGHT_THEME",
    "MAX_IMPORT_FILE_SIZE",
    "OCR_CHANDRA_ENABLED",
    "OCR_OLLAMA_ENABLED",
    "OCR_PADDLE_ENABLED",
    "OCR_TESSERACT_ENABLED",
]
