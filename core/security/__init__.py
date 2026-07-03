"""
core/security — Sicherheits-Infrastruktur für FINLAI.

Enthält:
  - validators.py: Eingabe-Validierung mit Allowlists (S1)
  - encryption.py: SecureStorage mit Fernet-Verschlüsselung (S2)
  - import_validator.py: Secure Import Gate (Magika + Format-Spezifika)
  - validation_report.py: Report-Datentypen (ValidationReport, Threat, Severity)
  - magika_adapter.py: Magika-Wrapper (AI-Dateityp-Erkennung)
  - sub_validators/: Format-spezifische Prüfer (XLSX, JSON, TXT, PDF,...)

Author: Patrick Riederich
Version: 1.1
"""

from core.security.import_validator import validate_import
from core.security.validation_report import (
    ImportType,
    Severity,
    Threat,
    ValidationReport,
)

__all__ = [
    "ImportType",
    "Severity",
    "Threat",
    "ValidationReport",
    "validate_import",
]
