"""
exceptions — Domain-Exception-Hierarchie für das Customer-Audit-Tool (R-Exc).

Schichtzugehörigkeit: domain/ — keine Imports aus äußeren Schichten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations


class CustomerAuditError(Exception):
    """Basis-Exception für das Customer-Audit-Tool."""


class AuditNotFoundError(CustomerAuditError):
    """Ein referenziertes Audit existiert nicht (z. B. Basis einer neuen Version)."""


class AuditModeViolationError(CustomerAuditError):
    """Ein Audit trägt Daten, die für seinen:class:`AuditMode` unzulässig sind.

    Konkret: ein Kunden-Audit (``CUSTOMER``) enthält Scan-
    Daten des eigenen Beraterrechners. Fail-closed — ein Fremd-Audit darf nie
    Eigenscan-Ergebnisse zeigen, weil die Scanner nicht auf der Mandanten-
    Maschine laufen.
    """
