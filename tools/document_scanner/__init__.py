"""
document_scanner — Drag&Drop-Scanner fuer verdaechtige Dokumente.

NoRisk's Antwort auf Patricks UX-Frage "Was tut ein User mit einem
verdaechtigen E-Mail-Anhang?". Statt die Datei in den Explorer zu
ziehen und doppelzuklicken, zieht der User sie in NoRisk. Dort:

1. Datei landet im Quarantaene-Ordner ``%TEMP%\\norisk_quarantine\\<uuid>``.
2. Datei wird mit Read-Only-Bit versehen (kein versehentliches Oeffnen).
3. ``core.security.validate_import`` laeuft (Magika + Sub-Validator).
4. UI zeigt Risiko-Score + Befunde + Reasoning.
5. User entscheidet: Loeschen / Speichern (mit Mark-of-the-Web) /
   trotzdem oeffnen (mit Warnung).

Auto-Cleanup beim App-Beenden.

Iteration 1: Skeleton, Dropzone, Quarantaene,
generische Validierung (Magika + GenericValidator + PDF-Deep-Scan).
Office-/Archive-/Skript-Analyzer folgen in Iter 2.
"""

from .tool import DocumentScannerTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["DocumentScannerTool"]
