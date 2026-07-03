"""
repository — Port (Interface) fuer Audit-Persistenz.

Review-Followup: Hexagonal Architecture verlangt,
dass die ``application``-Schicht gegen ein Interface (Port) in der
``domain``-Schicht programmiert und die ``data``-Schicht das Interface
implementiert (Adapter). Vorher importierte ``application/services.py``
direkt ``data.customer_audit_repository.CustomerAuditRepository`` —
das war eine Inversion-of-Control-Verletzung.

Use-Cases sollen ``AuditRepository`` als Type-Hint nutzen, nicht die
konkrete Klasse. Damit sind sie testbar ohne SQLCipher-Fixture und
unabhaengig von SQLite-Details.

Schichtzugehoerigkeit: domain/ — keine Imports aus aeusseren Schichten.
"""

from __future__ import annotations

from typing import Protocol

from tools.customer_audit.domain.entities import CustomerAuditResult


class AuditRepository(Protocol):
    """Persistenz-Port fuer Kunden-Audit-Ergebnisse.

    Konkrete Implementierungen liegen in ``data/``. Tests koennen ein
    Mock implementieren ohne die echte DB.
    """

    def save(self, result: CustomerAuditResult) -> CustomerAuditResult:
        """Speichert ein Audit-Ergebnis."""
        ...

    def set_subject_id(self, audit_id: str, subject_id: str) -> None:
        """Verknüpft ein Audit mit einem kanonischen Subjekt."""
        ...

    def mark_superseded(self, audit_id: str) -> None:
        """Markiert ein Audit als überholt (``is_latest=0``)."""
        ...

    def load_by_id(self, audit_id: str) -> CustomerAuditResult | None:
        """Laedt ein Audit anhand seiner ID."""
        ...

    def load_all(self, limit: int = 50) -> list[CustomerAuditResult]:
        """Laedt die letzten ``limit`` Audits (neueste zuerst)."""
        ...

    def load_all_for_backfill(self) -> list[CustomerAuditResult]:
        """Laedt ALLE Audits ohne Limit (Subjekt-Backfill)."""
        ...

    def load_by_firma(self, firmenname: str) -> list[CustomerAuditResult]:
        """Laedt alle Audits einer bestimmten Firma."""
        ...

    def delete(self, audit_id: str) -> bool:
        """Loescht ein Audit samt ganzer Versionskette (DSGVO Art. 17).

        Entfernt ALLE Versionen der Kette (``root_audit_id``). Gibt ``True``
        zurueck wenn mindestens eine Zeile existierte. Fuer das Loeschen einer
        EINZELNEN Version:meth:`delete_version`.
        """
        ...

    def delete_version(self, audit_id: str) -> bool:
        """Loescht GENAU diese eine Version (PK ``audit_id``); andere bleiben.

        Im Gegensatz zu:meth:`delete` (ganze Kette) entfernt dies nur die
        einzelne Version. War sie ``is_latest=1``, wird die neueste
        verbleibende Version der Kette wieder ``is_latest=1`` gehoben — sonst
        verschwaende der Kunde aus Dashboard/Listen-Filtern, obwohl noch
        Versionen existieren. Gibt ``True`` zurueck wenn die Version existierte.
        """
        ...

    def list_chain_audit_ids(self, audit_id: str) -> list[str]:
        """Liefert ALLE ``audit_id`` der Versionskette (root_audit_id).

        ``delete`` entfernt die ganze Kette physisch — die NIS2-Anonymisierung
        muss daher ueber ALLE Ketten-Mitglieder laufen, sonst bleiben PII von
        Vorgaenger-Versionen verwaist. ``[]`` wenn ``audit_id`` nicht existiert.
        """
        ...

    def list_summaries(self, limit: int = 50) -> list[dict]:
        """Kompakte Summary-Dicts der letzten Audits (UI-Liste)."""
        ...

    def latest_summary_by_subject(self, subject_id: str) -> dict | None:
        """Summary des jüngsten **aktuellen** Audits eines Subjekts."""
        ...

    def count_for_subject(self, subject_id: str) -> int:
        """Anzahl Audits (alle Versionen/Ketten) mit dieser ``subject_id``.

        Orphan-Check für den DSGVO-Art.-17-Löschpfad: nach dem Löschen
        einer Audit-Kette zeigt ``0`` an, dass kein Audit das Subjekt mehr hält.
        """
        ...
