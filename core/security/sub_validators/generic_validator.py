"""
generic_validator — Fallback-Validierer für nicht speziell abgedeckte Typen.

Prüft ausschließlich Magika-Ergebnis (Gefährliches Label) und Dateigröße.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.security.magika_adapter import DANGEROUS_LABELS, identify
from core.security.sub_validators.base import SubValidator
from core.security.validation_report import Severity, Threat, ValidationReport

# Harter Deckel für Fallback-Typen: 200 MB
MAX_GENERIC_SIZE_BYTES: int = 200 * 1024 * 1024


class GenericValidator(SubValidator):
    """Fallback für unbekannte oder nicht speziell abgedeckte Typen."""

    def validate(self, path: Path, report: ValidationReport) -> None:
        """Fügt Threats bei Größenüberschreitung oder gefährlichem Magika-Label an.

        Args:
            path: Zu prüfender Pfad.
            report: Report zum Anhängen.
        """
        size = path.stat().st_size
        if size > MAX_GENERIC_SIZE_BYTES:
            report.add(
                Threat(
                    code="GENERIC_FILE_TOO_LARGE",
                    severity=Severity.HIGH,
                    message=(
                        f"Datei zu groß ({size // (1024 * 1024)} MB). "
                        f"Limit: {MAX_GENERIC_SIZE_BYTES // (1024 * 1024)} MB."
                    ),
                    context={"size_bytes": size, "limit_bytes": MAX_GENERIC_SIZE_BYTES},
                )
            )

        ident = identify(path)
        if ident.label in DANGEROUS_LABELS:
            report.add(
                Threat(
                    code="GENERIC_DANGEROUS_CONTENT",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Inhalt erkannt als '{ident.label}' "
                        f"({ident.description}) — ausführbarer oder aktiver Code."
                    ),
                    context={
                        "detected_label": ident.label,
                        "mime_type": ident.mime_type,
                    },
                )
            )
