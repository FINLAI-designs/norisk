"""
base — Abstract Base Class für alle Sub-Validatoren.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from core.security.validation_report import ValidationReport


class SubValidator(ABC):
    """Basis-Klasse für format-spezifische Validierer.

    Sub-Validatoren melden Threats über ``report.add`` — sie werfen
    niemals Exceptions für erkannte Threats. Unerwartete System-Fehler
    (I/O, korrupte Pakete) werden als ``*_SCAN_ERROR``-Threat eingetragen.
    """

    @abstractmethod
    def validate(self, path: Path, report: ValidationReport) -> None:
        """Führt die format-spezifische Validierung durch.

        Args:
            path: Zu prüfende Datei (bereits auf Existenz geprüft).
            report: Report, an dem Threats angehängt werden.
        """
        raise NotImplementedError
