"""subject_backfill — Einmaliger Subjekt-Backfill der customer_audit-DB.

Verknüpft Bestands-Audits mit der kanonischen Subjekt-Identität (``subject_id``),
die vor fehlte, Migrations-Test-Plan §2 Schritt 4):

* ``AuditMode.SELF`` → eigenes Subjekt (Selbst-Audit der eigenen Org).
* ``AuditMode.CUSTOMER`` → Kunden-Subjekt per ``firmenname`` (find-or-create,
  Dedup per Name); ``branche``/``groesse``/Ansprechpartner werden aus den
  Kundenstammdaten ins Subjekt nachgezogen.

Läuft **nach** dem security_scoring-Backfill (der den Subjekt-Store hält). Der
Store wird ausschließlich über den core-Resolver bezogen — kein tool→tool-Import
 §3.2). Idempotent + marker-gesichert (``audit_migration_log``) analog
zur-Migration. Forward-only; die additive ``subject_id``-Spalte ist
abwärtskompatibel.

Schichtzugehörigkeit: application/ — Use-Case-Orchestrierung, kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from core.security_subject.ports import SubjectStore
from core.security_subject.resolver import create_subject_store
from tools.customer_audit.domain.entities import AuditMode
from tools.customer_audit.domain.repository import AuditRepository

log = get_logger(__name__)

_DB_NAME = "customer_audit"
_MIGRATION_ID = "t294_audit_subject_consolidation_v1"
_DEFAULT_SELF_NAME = "Mein System"


class AuditBackfillInconsistentError(RuntimeError):
    """Post-Backfill-Konsistenz verletzt: eligible Audits ohne subject_id.

    Wird VOR dem Idempotenz-Marker geworfen -> der Lauf gilt nicht als erledigt
    und wird beim naechsten Start wiederholt (selbstheilend). Der Boot-Aufrufer
    faengt fail-soft (blockiert den App-Start nie).
    """


def run_audit_subject_backfill(
    *,
    store: SubjectStore | None = None,
    repo: AuditRepository | None = None,
    default_self_name: str = _DEFAULT_SELF_NAME,
) -> dict[str, int | bool]:
    """Führt den Subjekt-Backfill der customer_audit-DB aus (idempotent).

    Args:
        store: SubjectStore (Default: production-Store über core-Resolver).
            Injizierbar für Tests.
        repo::class:`AuditRepository`-Port (Default: konkrete
            ``CustomerAuditRepository``, falls None). Tests injizieren ein Mock.
        default_self_name: Name des eigenen Subjekts, falls noch keines
            existiert (Self-Audit ohne vorhandenes eigenes Profil).

    Returns:
        Statistik-Dict (``skipped`` bei bereits gelaufener Migration bzw.
        fehlendem Store, sonst Zähler ``self_audits``/``client_audits``).
    """
    # Repo zuerst — sein Schema-Init legt ``audit_migration_log`` an, sodass
    # der Marker-Check unten auch beim allerersten App-Start sicher greift.
    if repo is None:
        # Composition-Root: application darf data für den Default anfassen.
        from tools.customer_audit.data.customer_audit_repository import (  # noqa: PLC0415
            CustomerAuditRepository,
        )

        repo = CustomerAuditRepository()

    if _migration_done():
        return {"skipped": True}

    store = store or create_subject_store()
    if store is None:
        log.info(
            "Audit-Subjekt-Backfill übersprungen — SubjectStore nicht verfügbar."
        )
        return {"skipped": True}

    self_count = 0
    client_count = 0
    skipped_no_name = 0
    for audit in repo.load_all_for_backfill():
        cd = audit.customer_data
        if audit.audit_mode is AuditMode.SELF:
            subject = store.ensure_self_subject(cd.firmenname or default_self_name)
            self_count += 1
        else:
            if not cd.firmenname.strip():
                # Ohne Firmenname kann kein Kunden-Subjekt angelegt werden.
                skipped_no_name += 1
                continue
            subject = store.find_or_create_client(cd.firmenname)
            store.update_stammdaten(
                subject.subject_id,
                branche=cd.branche,
                groesse=cd.unternehmensgroesse,
                contact=cd.ansprechpartner_name,
            )
            client_count += 1
        repo.set_subject_id(audit.audit_id, subject.subject_id)

    # Konsistenz-Assertion "+ Assertion"): jedes eligible Audit muss nach
    # dem Backfill ein subject_id tragen. Wirft VOR dem Marker (selbstheilender
    # Retry). set_subject_id haelt Spalte + result_json synchron -> der Re-Load
    # liefert den Ist-Stand.
    _assert_audit_backfill_consistent(repo)

    stats: dict[str, int | bool] = {
        "self_audits": self_count,
        "client_audits": client_count,
        "skipped_no_name": skipped_no_name,
    }
    if skipped_no_name:
        log.warning(
            "Audit-Subjekt-Backfill: %d Kunden-Audits ohne Firmenname "
            "uebersprungen (nicht verknuepfbar).",
            skipped_no_name,
        )
    _record_migration(self_count + client_count)
    log.info("Audit-Subjekt-Backfill abgeschlossen: %s", stats)
    return stats


def _assert_audit_backfill_consistent(repo: AuditRepository) -> None:
    """Konsistenz-Assertion nach dem Audit-Subjekt-Backfill.

    Eligibel = SELF-Audit ODER Kunden-Audit mit nicht-leerem Firmenname; diese
    muessen nach dem Backfill ein ``subject_id`` tragen. Kunden-Audits OHNE
    Firmenname sind bewusst nicht verknuepfbar (kein Identitaets-Anker) und
    daher NICHT eligibel. Loggt laut + wirft bei Verletzung.

    Raises:
        AuditBackfillInconsistentError: Mindestens ein eligibles Audit blieb
            ohne ``subject_id``.
    """
    unlinked = [
        audit.audit_id
        for audit in repo.load_all_for_backfill()
        if not audit.subject_id
        and (
            audit.audit_mode is AuditMode.SELF
            or audit.customer_data.firmenname.strip()
        )
    ]
    if unlinked:
        log.error(
            "Audit-Subjekt-Backfill INKONSISTENT: %d eligible Audits ohne "
            "subject_id (z.B. %s).",
            len(unlinked),
            unlinked[:3],
        )
        raise AuditBackfillInconsistentError(
            f"{len(unlinked)} eligible Audits ohne subject_id nach dem Backfill."
        )


# ---------------------------------------------------------------------------
# Marker (Idempotenz) — nutzt die bestehende ``audit_migration_log``-Tabelle.
# ---------------------------------------------------------------------------


def _migration_done() -> bool:
    """True, wenn der Audit-Subjekt-Backfill bereits gelaufen ist."""
    db = EncryptedDatabase(_DB_NAME)
    with db.connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
            (_MIGRATION_ID,),
        ).fetchone()
    return row is not None


def _record_migration(rows: int) -> None:
    """Setzt den Idempotenz-Marker mit der Anzahl verknüpfter Audits."""
    db = EncryptedDatabase(_DB_NAME)
    with db.connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO audit_migration_log "
            "(migration_id, completed_at, rows_copied, source) "
            "VALUES (?, ?, ?, ?)",
            (
                _MIGRATION_ID,
                datetime.now(tz=UTC).isoformat(),
                rows,
                "t294_subject",
            ),
        )
