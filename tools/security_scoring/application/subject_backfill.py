"""subject_backfill — Einmaliger Subjekt-Backfill der security_scoring-DB.

Verknüpft Bestandsdaten (Org-Assessments, Score-/Hardening-Verläufe) mit der
kanonischen Subjekt-Identität (``subject_id``), die vor fehlte:

* Org-Assessments sind Selbstbewertungen der eigenen Organisation → eigenes Subjekt.
* Technische Scores keyen auf Freitext-``target_name``; der Self-Name (==
  eigenes System) → eigenes Subjekt, jeder andere Name → Kunden-Subjekt
  (find-or-create, Dedup per Name).

Idempotent + marker-gesichert (``subject_migration_log``) analog zur-
Migration. Forward-only; additive Spalten sind abwärtskompatibel.

Schichtzugehörigkeit: application/ — Use-Case-Orchestrierung, kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.logger import get_logger
from core.security_subject.ports import SubjectStore
from tools.security_scoring.application.subject_store import (
    create_default_subject_store,
)
from tools.security_scoring.data.hardening_score_repository import (
    HardeningScoreRepository,
)
from tools.security_scoring.data.org_assessment_repository import (
    OrgAssessmentRepository,
)
from tools.security_scoring.data.score_repository import ScoreRepository

log = get_logger(__name__)

_DB_NAME = "security_scoring"
_MIGRATION_ID = "t294_subject_consolidation_v1"
_DEFAULT_SELF_NAME = "Mein System"

_MARKER_SCHEMA = """
CREATE TABLE IF NOT EXISTS subject_migration_log (
    migration_id  TEXT PRIMARY KEY,
    completed_at  TEXT NOT NULL,
    stats_json    TEXT NOT NULL DEFAULT '{}'
);
"""


class SubjectBackfillInconsistentError(RuntimeError):
    """Post-Backfill-Konsistenz verletzt: eligible Datensaetze ohne subject_id.

    Wird vom Konsistenz-Check nach dem Subjekt-Backfill geworfen,
    BEVOR der Idempotenz-Marker gesetzt wird -> der Lauf gilt nicht als
    erledigt und wird beim naechsten Start wiederholt (selbstheilend). Der
    Boot-Aufrufer faengt fail-soft (blockiert den App-Start nie).
    """


def run_subject_backfill(
    *,
    store: SubjectStore | None = None,
    org_repo: OrgAssessmentRepository | None = None,
    score_repo: ScoreRepository | None = None,
    hardening_repo: HardeningScoreRepository | None = None,
    default_self_name: str = _DEFAULT_SELF_NAME,
) -> dict[str, int | bool]:
    """Führt den Subjekt-Backfill der security_scoring-DB aus (idempotent).

    Args:
        store: SubjectStore (Default: production-Store). Injizierbar für Tests.
        org_repo: OrgAssessmentRepository (Default-Bau, falls None).
        score_repo: ScoreRepository (Default-Bau, falls None).
        hardening_repo: HardeningScoreRepository (Default-Bau, falls None).
        default_self_name: Name des eigenen Subjekts, falls noch keines existiert.

    Returns:
        Statistik-Dict (``skipped`` bei bereits gelaufener Migration, sonst
        Zähler ``org``/``score_targets``/``hardening_targets``).
    """
    if _migration_done():
        return {"skipped": True}

    store = store or create_default_subject_store()
    if store is None:
        log.info("Subjekt-Backfill übersprungen — SubjectStore nicht verfügbar.")
        return {"skipped": True}

    org_repo = org_repo or OrgAssessmentRepository()
    score_repo = score_repo or ScoreRepository()
    hardening_repo = hardening_repo or HardeningScoreRepository()

    self_subject = store.ensure_self_subject(default_self_name)
    self_name = self_subject.name

    # 1. Org-Assessments → eigenes Subjekt (Selbstbewertung der eigenen Org).
    org_count = 0
    for audit_id in org_repo.list_audit_ids():
        org_repo.set_subject_id(audit_id, self_subject.subject_id)
        org_count += 1

    # 2. + 3. Score- und Hardening-Verläufe → Subjekt per target_name.
    score_names = score_repo.distinct_targets()
    score_targets = _map_targets(
        score_names, store, self_name, self_subject.subject_id
    )
    for target, sid in score_targets.items():
        score_repo.set_subject_id_for_target(target, sid)

    hardening_names = hardening_repo.list_targets()
    hardening_targets = _map_targets(
        hardening_names, store, self_name, self_subject.subject_id
    )
    for target, sid in hardening_targets.items():
        hardening_repo.set_subject_id_for_target(target, sid)

    # Leere Ziel-Namen sind nicht verknuepfbar -> explizit zaehlen statt still
    # verschlucken: skips sichtbar machen).
    skipped_empty = (len(score_names) - len(score_targets)) + (
        len(hardening_names) - len(hardening_targets)
    )

    stats: dict[str, int | bool] = {
        "org": org_count,
        "score_targets": len(score_targets),
        "hardening_targets": len(hardening_targets),
        "skipped_empty_targets": skipped_empty,
    }

    # Konsistenz-Assertion "+ Assertion"): nach dem Backfill darf KEIN
    # eligibler Datensatz mehr ohne subject_id sein. Wirft VOR dem Marker.
    _assert_backfill_consistent(org_repo, score_repo, hardening_repo)

    if skipped_empty:
        log.warning(
            "Subjekt-Backfill: %d leere Ziel-Namen uebersprungen "
            "(nicht verknuepfbar).",
            skipped_empty,
        )
    _record_migration(stats)
    log.info("Subjekt-Backfill abgeschlossen: %s", stats)
    return stats


def _assert_backfill_consistent(
    org_repo: OrgAssessmentRepository,
    score_repo: ScoreRepository,
    hardening_repo: HardeningScoreRepository,
) -> None:
    """Konsistenz-Assertion nach dem Subjekt-Backfill.

    Verifiziert, dass kein eligibler Datensatz (Org-Assessment bzw.
    benennbares Score-/Hardening-Ziel) ohne ``subject_id`` verbleibt. Loggt
    laut auf ERROR und wirft:class:`SubjectBackfillInconsistentError` bei
    Verletzung.

    Raises:
        SubjectBackfillInconsistentError: Mindestens ein eligibler Datensatz
            blieb nach dem Backfill ohne ``subject_id``.
    """
    unlinked_org = org_repo.count_without_subject()
    unlinked_score = score_repo.count_targets_without_subject()
    unlinked_hardening = hardening_repo.count_targets_without_subject()
    total = unlinked_org + unlinked_score + unlinked_hardening
    if total:
        log.error(
            "Subjekt-Backfill INKONSISTENT: %d Org + %d Score-Targets + %d "
            "Hardening-Targets ohne subject_id nach dem Lauf.",
            unlinked_org,
            unlinked_score,
            unlinked_hardening,
        )
        raise SubjectBackfillInconsistentError(
            f"Eligible Datensaetze ohne subject_id nach Backfill: "
            f"org={unlinked_org}, score={unlinked_score}, "
            f"hardening={unlinked_hardening}."
        )


def _map_targets(
    targets: list[str],
    store: SubjectStore,
    self_name: str,
    self_id: str,
) -> dict[str, str]:
    """Bildet Freitext-``target_name`` auf ``subject_id`` ab.

    Der Self-Name → eigenes Subjekt; jeder andere Name → Kunden-Subjekt
    (find-or-create). Leere Namen werden übersprungen.

    Args:
        targets: Distinkte Ziel-Namen.
        store: SubjectStore.
        self_name: Name des eigenen Subjekts.
        self_id: subject_id des eigenen Subjekts.

    Returns:
        Mapping target_name → subject_id.
    """
    mapping: dict[str, str] = {}
    for target in targets:
        if not target or not target.strip():
            continue
        if target == self_name:
            mapping[target] = self_id
        else:
            mapping[target] = store.find_or_create_client(target).subject_id
    return mapping


# ---------------------------------------------------------------------------
# Marker (Idempotenz)
# ---------------------------------------------------------------------------


def _migration_done() -> bool:
    """True, wenn der Backfill bereits gelaufen ist."""
    db = EncryptedDatabase(_DB_NAME)
    with db.connection() as conn:
        conn.executescript(_MARKER_SCHEMA)
        row = conn.execute(
            "SELECT 1 FROM subject_migration_log WHERE migration_id = ?",
            (_MIGRATION_ID,),
        ).fetchone()
    return row is not None


def _record_migration(stats: dict[str, int | bool]) -> None:
    """Setzt den Idempotenz-Marker mit Backfill-Statistik."""
    db = EncryptedDatabase(_DB_NAME)
    with db.connection() as conn:
        conn.executescript(_MARKER_SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO subject_migration_log "
            "(migration_id, completed_at, stats_json) VALUES (?, ?, ?)",
            (
                _MIGRATION_ID,
                datetime.now(UTC).isoformat(),
                json.dumps(stats, ensure_ascii=False),
            ),
        )
