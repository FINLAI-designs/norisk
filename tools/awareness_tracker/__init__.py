"""awareness_tracker — Schulungs- und Phishing-Sim-Tracker.

Implementiert NIST CSF 2.0 PR.AT (Awareness & Training) und unterstuetzt
DSGVO Art. 32 / NIS2 Art. 21(2)(g) Awareness-Anforderungen.

 Audit-Paket-3:
- **3a** — Skeleton + Domain (Employee, Training) + DB-Repo + GUI-Geruest.
- **3b** — Schulungs-Tracker GUI (Renewal-Reminder, ICS-Export).
- **3c** — Phishing-Sim-Logger (Kampagnen-Tracking, Klickraten).
"""

from .tool import AwarenessTrackerTool  # noqa: F401 — Re-Export ueber __all__

__all__ = ["AwarenessTrackerTool"]
