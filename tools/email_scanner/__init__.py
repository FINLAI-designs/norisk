"""email_scanner — E-Mail-Anhang-Scanner (NoRisk by FINLAI).

Analysiert.eml- und.msg-Dateien, extrahiert Attachments und routet
diese durch den Secure Import Validator sowie den PDF-Risk-Scanner.
Das Tool öffnet niemals HTML-Bodies im Browser-Renderer und führt
Anhänge nicht aus — nur statische Analyse + Quarantäne.

Author: Patrick Riederich
Version: 1.0
"""

from .tool import EmailScannerTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["EmailScannerTool"]
