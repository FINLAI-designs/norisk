"""core.security_subject — Kanonische, tool-übergreifende Subjekt-Identität.

Das *Subjekt* ist die Sache, die bewertet wird: das eigene System ODER ein
externer Kunde/Mandant. Vor war dieselbe Identität dreifach und
unverbunden modelliert (``customer_audit.firmenname``, ``security_scoring``-
``target_name`` + ``SystemProfile.system_type``, frische ``audit_id``-UUIDs).

Diese Schicht stellt EINE kanonische Entität (:class:`Subject`) plus einen
Port (:class:`SubjectStore`) bereit. Die physische Persistenz bleibt in der
``security_scoring``-DB (Tabelle ``system_profiles``); deren Repository
implementiert den Port. So referenzieren Audit, Scoring und
Dashboard dieselbe ``subject_id``, ohne dass ein Tool ein anderes importiert.

Schichtzugehörigkeit: core/ — reine Modelle + Port, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.security_subject.models import Subject, SubjectKind
from core.security_subject.ports import SubjectStore

__all__ = ["Subject", "SubjectKind", "SubjectStore"]
