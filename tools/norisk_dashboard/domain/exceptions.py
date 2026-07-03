"""exceptions — Fehler-Hierarchie des Cockpit-Workflow-Tabs, R-Exc).

Pro Tool eine eigene Exception-Hierarchie (coding-rules R-Exc): eine Basis
:class:`WorkflowError` und daraus abgeleitete, schichtspezifische Fehler. Die
``data/``-Schicht uebersetzt rohe Infrastruktur-/Validierungsfehler (z. B. ein
``ValueError`` aus:func:`normalize_status`) in:class:`WorkflowDataError`, damit
Aufrufer gegen einen Tool-eigenen Vertrag fangen — kein rohes ``ValueError`` aus
dem Repository, „Konsequenzen").

Schicht: ``domain/`` — importiert nur die Standardbibliothek.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations


class WorkflowError(Exception):
    """Basis aller Fehler des Cockpit-Workflow-Tabs."""


class WorkflowDataError(WorkflowError):
    """Fehler aus der ``data/``-Schicht (Persistenz/Validierung des Fortschritts).

    Wird u. a. ausgeloest, wenn ein ungueltiger Statuswert persistiert werden
    soll (das rohe ``ValueError`` aus:func:`normalize_status` wird hier
    kontextualisiert, ``raise... from`` erhaelt die Ursache).
    """


__all__ = ["WorkflowDataError", "WorkflowError"]
