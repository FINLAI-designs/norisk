"""
customer_audit_repository — Persistenz fuer Kunden-Audit-Ergebnisse.

Implementiert CRUD-Operationen mit EncryptedDatabase (SQLCipher).
Speichert Ergebnisse als JSON-Blob in einer eigenen Tabelle.

Sicherheitsdesign:
  - AES-256 Vollverschluesselung via EncryptedDatabase
  - Kein sqlite3.connect direkt
  - Kundendaten werden nicht im Klartext geloggt

Schichtzugehoerigkeit: data/ — darf DB-Zugriff und JSON-Serialisierung nutzen.

Author: Patrick Riederich
Version: 1.1-Review-Followup: Cross-DB-Migration aus
``customer_assessment.db`` und Migrations-Marker.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from core.database.encrypted_db import EncryptedDatabase
from core.database.schema_utils import ensure_column
from core.logger import get_logger
from tools.customer_audit.domain.entities import (
    CustomerAuditResult,
    unescape_strings,
    unescape_text,
)

log = get_logger(__name__)

_DB_NAME = "customer_audit"
_OLD_DB_NAME = "customer_assessment"
_MIGRATION_ID = "t100_assessment_to_audit_v1"
_VERSIONING_MIGRATION_ID = "t306_audit_versioning_v1"
_UNESCAPE_MIGRATION_ID = "t315_escape_at_render_v1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS customer_audits (
    audit_id TEXT PRIMARY KEY,
    firmenname    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    overall_score REAL NOT NULL,
    risk_level    TEXT NOT NULL,
    result_json   TEXT NOT NULL,
    subject_id    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ca_created
    ON customer_audits(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ca_firma
    ON customer_audits(firmenname);

CREATE TABLE IF NOT EXISTS audit_migration_log (
    migration_id  TEXT PRIMARY KEY,
    completed_at  TEXT NOT NULL,
    rows_copied   INTEGER NOT NULL,
    source        TEXT NOT NULL
);
"""


class CustomerAuditRepository:
    """SQLCipher-Repository fuer Kunden-Audit-Ergebnisse.

    Tabelle ``customer_assessments`` wurde zu
    ``customer_audits`` umbenannt. Beim ersten Init nach dem Rename
    laeuft eine einmalige Migration ueber zwei Pfade:

    1. **In-File-Pfad:** Falls dieselbe DB-Datei bereits beide Tabellen
       hat (Test-Fixtures, alte App-Builds), wird ``customer_assessments``
       in ``customer_audits`` kopiert.
    2. **Cross-File-Pfad:** Falls eine separate ``customer_assessment.db``
       existiert (Patricks eigener Stand + alle in-place-Updates), wird
       sie als zweite ``EncryptedDatabase``-Instanz geoeffnet (eigener
       HKDF-abgeleiteter Cipher-Key) und die Zeilen werden in die neue
       DB gespiegelt. Anschliessend wird die Quelle nach
       ``customer_assessment.db.migrated_to_audit.bak`` umbenannt.

    Beide Pfade sind idempotent ueber ``audit_migration_log`` —
    ein erfolgreicher Lauf wird mit Marker ``t100_assessment_to_audit_v1``
    gespeichert, weitere Aufrufe sind no-ops.
    """

    def __init__(self) -> None:
        """Initialisiert die Datenbank und erstellt das Schema."""
        self._db = EncryptedDatabase(_DB_NAME)
        self._init_schema()
        self._migrate_from_assessments()
        self._migrate_versioning()
        self._migrate_unescape()

    def _init_schema(self) -> None:
        """Erstellt die Tabellen falls noch nicht vorhanden.

        ``subject_id`` wird additiv via:func:`ensure_column`
        nachgezogen (Bestands-DBs ohne die Spalte) und erst danach
        indiziert — die Reihenfolge ist Pflicht, sonst läuft das
        ``CREATE INDEX`` auf eine noch fehlende Spalte.
        """
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
            ensure_column(conn, "customer_audits", "subject_id", "TEXT DEFAULT ''")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ca_subject "
                "ON customer_audits(subject_id)"
            )
            # additive Versionierungs-Spalten (Edit = neue Version).
            ensure_column(conn, "customer_audits", "version", "INTEGER DEFAULT 1")
            ensure_column(
                conn, "customer_audits", "supersedes_audit_id", "TEXT DEFAULT ''"
            )
            ensure_column(
                conn, "customer_audits", "root_audit_id", "TEXT DEFAULT ''"
            )
            ensure_column(conn, "customer_audits", "is_latest", "INTEGER DEFAULT 1")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ca_latest "
                "ON customer_audits(subject_id, is_latest)"
            )

    def _migration_done(self) -> bool:
        """True, wenn die-Migration bereits erfolgreich war."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                (_MIGRATION_ID,),
            ).fetchone()
        return row is not None

    def _record_migration(self, rows_copied: int, source: str) -> None:
        """Markiert die Migration als abgeschlossen."""
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO audit_migration_log "
                "(migration_id, completed_at, rows_copied, source) "
                "VALUES (?, ?, ?, ?)",
                (
                    _MIGRATION_ID,
                    datetime.now(tz=UTC).isoformat(),
                    rows_copied,
                    source,
                ),
            )

    def _migrate_from_assessments(self) -> None:
        """Einmalige Daten-Migration aus der alten Tabelle/DB.

        Zwei Pfade, beide gegated durch ``audit_migration_log``.
        """
        if self._migration_done():
            return

        rows_in_file = self._migrate_in_file()
        rows_cross = self._migrate_cross_file()

        if rows_in_file or rows_cross:
            self._record_migration(
                rows_copied=rows_in_file + rows_cross,
                source=("in_file" if rows_in_file else "")
                + ("+cross_file" if rows_cross else ""),
            )
            log.info(
                "T-100-Migration abgeschlossen: %d Eintraege uebernommen "
                "(in_file=%d, cross_file=%d).",
                rows_in_file + rows_cross,
                rows_in_file,
                rows_cross,
            )
        else:
            # Keine Quelle gefunden — Marker trotzdem setzen, damit der
            # Cross-File-Check nicht bei jedem Start neu laeuft.
            self._record_migration(rows_copied=0, source="no_source")

    def _migrate_in_file(self) -> int:
        """Kopiert ``customer_assessments`` -> ``customer_audits`` in
        derselben DB-Datei. Gibt die Anzahl uebernommener Zeilen zurueck.
        """
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='customer_assessments'"
            )
            if not cur.fetchone():
                return 0
            log.info(
                "Migration (in_file): kopiere customer_assessments -> "
                "customer_audits"
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO customer_audits (
                    audit_id, firmenname, created_at,
                    overall_score, risk_level, result_json
                )
                SELECT assessment_id, firmenname, created_at,
                       overall_score, risk_level, result_json
                FROM customer_assessments
                """
            )
            row = conn.execute(
                "SELECT changes()"
            ).fetchone()
            return int(row[0]) if row else 0

    def _migrate_cross_file(self) -> int:
        """Kopiert Eintraege aus separater ``customer_assessment.db``.

        Oeffnet die alte DB als zweite ``EncryptedDatabase``-Instanz
        (eigener Cipher-Key durch HKDF-Domain-Separation auf
        ``"db:customer_assessment"``), liest die ``customer_assessments``-
        Zeilen und schreibt sie in die neue DB. Bei Erfolg wird die
        Quelle nach ``.migrated_to_audit.bak`` umbenannt.
        """
        old_db_path = self._db.db_path.with_name(f"{_OLD_DB_NAME}.db")
        if not old_db_path.exists():
            return 0

        log.info(
            "Migration (cross_file): finde alte DB %s — versuche Lese-"
            "Zugriff via separater EncryptedDatabase-Instanz.",
            old_db_path,
        )
        try:
            old_db = EncryptedDatabase(_OLD_DB_NAME)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Migration (cross_file): alte DB nicht oeffenbar (%s) — "
                "Datei wird liegen gelassen, manuelle Pruefung noetig.",
                exc,
            )
            return 0

        try:
            with old_db.connection() as src_conn:
                src_rows = src_conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='customer_assessments'"
                ).fetchone()
                if not src_rows:
                    log.info(
                        "Migration (cross_file): alte DB enthaelt keine "
                        "customer_assessments-Tabelle — vermutlich vorher "
                        "bereits leer migriert."
                    )
                    return 0
                rows = src_conn.execute(
                    "SELECT assessment_id, firmenname, created_at, "
                    "overall_score, risk_level, result_json "
                    "FROM customer_assessments"
                ).fetchall()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Migration (cross_file): Lesen aus alter DB fehlgeschlagen "
                "(%s). Datei wird liegen gelassen.",
                exc,
            )
            return 0

        if not rows:
            return 0

        with self._db.connection() as dst_conn:
            dst_conn.executemany(
                "INSERT OR IGNORE INTO customer_audits "
                "(audit_id, firmenname, created_at, "
                " overall_score, risk_level, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )

        try:
            backup_path = old_db_path.with_suffix(
                ".db.migrated_to_audit.bak"
            )
            old_db_path.rename(backup_path)
            log.info(
                "Migration (cross_file): %d Zeilen uebernommen; alte DB "
                "umbenannt zu %s",
                len(rows),
                backup_path.name,
            )
        except OSError as exc:
            log.warning(
                "Migration (cross_file): Umbenennen der alten DB "
                "fehlgeschlagen (%s) — Daten sind aber bereits in der "
                "neuen DB. Datei kann manuell entfernt werden.",
                exc,
            )

        return len(rows)

    def _migrate_versioning(self) -> None:
        """: normalisiert ``root_audit_id`` für Bestandszeilen (idempotent).

        Setzt bei allen Zeilen ohne ``root_audit_id`` die Wurzel auf die eigene
        ``audit_id`` (jedes Bestands-Audit ist seine eigene Ketten-Wurzel;
        ``version=1``/``is_latest=1`` greifen über die Spalten-Defaults). Der
        Marker ``t306_audit_versioning_v1`` in ``audit_migration_log`` macht den
        Lauf idempotent — ein zweiter Aufruf ist ein no-op.
        """
        with self._db.connection() as conn:
            done = conn.execute(
                "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                (_VERSIONING_MIGRATION_ID,),
            ).fetchone()
            if done:
                return
            cur = conn.execute(
                "UPDATE customer_audits SET root_audit_id = audit_id "
                "WHERE root_audit_id IS NULL OR root_audit_id = ''"
            )
            rows = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            conn.execute(
                "INSERT OR REPLACE INTO audit_migration_log "
                "(migration_id, completed_at, rows_copied, source) "
                "VALUES (?, ?, ?, ?)",
                (
                    _VERSIONING_MIGRATION_ID,
                    datetime.now(tz=UTC).isoformat(),
                    rows,
                    "t306_versioning",
                ),
            )
        log.info("T-306-Versionierungs-Migration: %d Zeilen normalisiert", rows)

    def _migrate_unescape(self) -> None:
        """/: einmaliger Unescape-Backfill (escape-at-render).

        Bis wurden Freitexte beim Persistieren HTML-escaped
        (``Müller &amp; Co.``). Seit enthält die DB Klartext und
        jede markup-interpretierende Senke escaped selbst. Dieser Lauf
        ent-escaped alle Bestandszeilen (``result_json``-Payload rekursiv
        plus die denormalisierte ``firmenname``-Spalte) genau EINMAL.

        Idempotenz hängt allein am Marker ``t315_escape_at_render_v1`` —
        ein Doppellauf würde legitime Literal-Entities zerstören, deshalb
        läuft alles in EINER Transaktion (Marker im selben Commit).
        Forward-only ohne Backup: Altdaten sind Testdaten/022).
        Zeilen mit korruptem JSON werden übersprungen und nur mit
        Fehler-TYP geloggt (keine Kundendaten im Log).
        """
        migrated = 0
        skipped = 0
        with self._db.connection() as conn:
            done = conn.execute(
                "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                (_UNESCAPE_MIGRATION_ID,),
            ).fetchone()
            if done:
                return
            rows = conn.execute(
                "SELECT audit_id, firmenname, result_json FROM customer_audits"
            ).fetchall()
            for audit_id, firmenname, payload in rows:
                try:
                    neu_json = json.dumps(
                        unescape_strings(json.loads(payload)),
                        ensure_ascii=False,
                    )
                except (json.JSONDecodeError, TypeError, RecursionError) as exc:
                    log.warning(
                        "T-315-Migration: Payload von Zeile %s übersprungen (%s)",
                        str(audit_id)[:8],
                        type(exc).__name__,
                    )
                    skipped += 1
                    # Die denormalisierte Spalte hängt nicht am Payload —
                    # sie wird trotzdem ent-escaped (Review-Finding).
                    conn.execute(
                        "UPDATE customer_audits SET firmenname = ? "
                        "WHERE audit_id = ?",
                        (unescape_text(firmenname or ""), audit_id),
                    )
                    continue
                conn.execute(
                    "UPDATE customer_audits "
                    "SET firmenname = ?, result_json = ? WHERE audit_id = ?",
                    (unescape_text(firmenname or ""), neu_json, audit_id),
                )
                migrated += 1
            conn.execute(
                "INSERT OR REPLACE INTO audit_migration_log "
                "(migration_id, completed_at, rows_copied, source) "
                "VALUES (?, ?, ?, ?)",
                (
                    _UNESCAPE_MIGRATION_ID,
                    datetime.now(tz=UTC).isoformat(),
                    migrated,
                    "t315_escape_at_render",
                ),
            )
        log.info(
            "T-315-Unescape-Migration: %d Zeilen migriert, %d übersprungen",
            migrated,
            skipped,
        )

    def save(self, result: CustomerAuditResult) -> CustomerAuditResult:
        """Speichert ein Audit-Ergebnis (Upsert per ``audit_id``).

        Setzt audit_id und created_at falls noch nicht vorhanden.:
        Immutabilität wird auf der Use-Case-Ebene erzwungen (jede neue Version
        bekommt eine **neue** ``audit_id`` über
:class:`CreateVersionUseCase`) — daher überschreibt der Upsert hier nie
        eine bestehende Version.

        Args:
            result: Zu speicherndes Ergebnis.

        Returns:
            Gespeichertes Ergebnis (mit gesetzter ID und Datum).
        """
        if not result.audit_id:
            result.audit_id = str(uuid.uuid4())
        if not result.created_at:
            result.created_at = datetime.now(tz=UTC).isoformat()

        # Ketten-Wurzel ableiten, ohne die frozen Entity zu mutieren —
        # ein Neu-Audit (root leer) ist seine eigene Wurzel. Spalte UND
        # result_json-Blob werden konsistent gehalten. Ein frisch gespeichertes
        # Audit ist immer is_latest=1; den Vorgänger setzt CreateVersionUseCase
        # via mark_superseded auf 0.
        root_id = result.root_audit_id or result.audit_id
        payload = result.to_dict()
        payload["root_audit_id"] = root_id

        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO customer_audits
                    (audit_id, firmenname, created_at,
                     overall_score, risk_level, result_json, subject_id,
                     version, supersedes_audit_id, root_audit_id, is_latest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    result.audit_id,
                    result.customer_data.firmenname,
                    result.created_at,
                    result.overall_score,
                    result.risk_level,
                    json.dumps(payload),
                    result.subject_id,
                    result.version,
                    result.supersedes_audit_id,
                    root_id,
                ),
            )
        # DSGVO Art. 5: Firmennamen NICHT in den App-Log schreiben (App-Log
        # läuft unverschlüsselt im Filesystem). Identifikation über
        # audit_id-Prefix reicht für Debugging — Firmenname-Lookup
        # geht über die Encrypted-DB via load_by_id.
        log.debug("Audit %s gespeichert", result.audit_id[:8])
        return result

    def mark_superseded(self, audit_id: str) -> None:
        """Markiert ein Audit als nicht mehr aktuell.

        Wird vom:class:`CreateVersionUseCase` auf den Vorgänger angewandt,
        nachdem eine neue Version gespeichert wurde — danach ist nur die neue
        Version ``is_latest=1`` (Dashboard/Signals/Listen-Filter).

        Args:
            audit_id: UUID des überholten Audits.
        """
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE customer_audits SET is_latest = 0 WHERE audit_id = ?",
                (audit_id,),
            )

    def set_subject_id(self, audit_id: str, subject_id: str) -> None:
        """Verknüpft ein Audit mit einem kanonischen Subjekt.

        Setzt sowohl die ``subject_id``-Spalte (Join-/Backfill-Schlüssel) als
        auch das ``subject_id``-Feld im ``result_json``-Blob, damit Spalte und
        serialisiertes Ergebnis konsistent bleiben: Spalte ist
        Source-of-Truth für Joins).

        Args:
            audit_id: UUID des Audits.
            subject_id: UUID des verknüpften Subjekts.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT result_json FROM customer_audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return
            try:
                data = json.loads(row[0])
                data["subject_id"] = subject_id
                new_json = json.dumps(data)
            except (json.JSONDecodeError, TypeError):
                # Blob unlesbar — nur die Spalte setzen, Blob unverändert lassen.
                new_json = row[0]
            conn.execute(
                "UPDATE customer_audits SET subject_id = ?, result_json = ? "
                "WHERE audit_id = ?",
                (subject_id, new_json, audit_id),
            )

    def count_for_subject(self, subject_id: str) -> int:
        """Anzahl customer_audits-Zeilen mit dieser ``subject_id`` (alle Versionen).

        Orphan-Check fuer den DSGVO-Art.-17-Loeschpfad: 0 = kein Audit
        haelt das Subjekt mehr. Leere ``subject_id`` -> 0 (kein Match auf den
        Default-Leerwert anderer Zeilen).
        """
        if not subject_id:
            return 0
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM customer_audits WHERE subject_id = ?",
                (subject_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def load_all_for_backfill(self) -> list[CustomerAuditResult]:
        """Lädt ALLE Audits (ohne Limit) für den Subjekt-Backfill.

        Im Unterschied zu:meth:`load_all` gibt es kein ``LIMIT`` und keine
        Sortierung — der einmalige Backfill verarbeitet den Gesamtbestand.

        Returns:
            Liste aller deserialisierbaren:class:`CustomerAuditResult`.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT result_json FROM customer_audits"
            ).fetchall()

        results: list[CustomerAuditResult] = []
        for (result_json,) in rows:
            try:
                results.append(
                    CustomerAuditResult.from_dict(json.loads(result_json))
                )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Audit konnte nicht geladen werden: %s", exc)
        return results

    def load_by_id(self, audit_id: str) -> CustomerAuditResult | None:
        """Lädt ein Audit anhand seiner ID.

        Args:
            audit_id: UUID des Audits.

        Returns:
            CustomerAuditResult oder None wenn nicht gefunden.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT result_json FROM customer_audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()

        if not row:
            return None
        try:
            return CustomerAuditResult.from_dict(json.loads(row[0]))
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            log.warning(
                "Audit %s konnte nicht geladen werden: %s", audit_id[:8], exc
            )
            return None

    def load_all(self, limit: int = 50) -> list[CustomerAuditResult]:
        """Lädt alle gespeicherten Audits (neueste zuerst).

        Args:
            limit: Maximale Anzahl.

        Returns:
            Liste von CustomerAuditResult.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT result_json FROM customer_audits
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        results: list[CustomerAuditResult] = []
        for (result_json,) in rows:
            try:
                results.append(
                    CustomerAuditResult.from_dict(json.loads(result_json))
                )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Audit konnte nicht geladen werden: %s", exc)
        return results

    def load_by_firma(self, firmenname: str) -> list[CustomerAuditResult]:
        """Lädt alle Audits für eine bestimmte Firma.

        Args:
            firmenname: Name der Firma (exakter Match).

        Returns:
            Liste von CustomerAuditResult, neueste zuerst.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT result_json FROM customer_audits
                WHERE firmenname = ?
                ORDER BY created_at DESC
                """,
                (firmenname,),
            ).fetchall()

        results: list[CustomerAuditResult] = []
        for (result_json,) in rows:
            try:
                results.append(
                    CustomerAuditResult.from_dict(json.loads(result_json))
                )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Audit konnte nicht geladen werden: %s", exc)
        return results

    def list_chain_audit_ids(self, audit_id: str) -> list[str]:
        """Liefert ALLE ``audit_id`` der Versionskette von ``audit_id``.

        Ermittelt ueber ``root_audit_id`` (Ketten-Schluessel) dieselbe Menge,
        die:meth:`delete` physisch entfernt — die NIS2-Anonymisierung kann so
        ueber die ganze Kette laufen statt nur ueber das eine ``audit_id``.

        Args:
            audit_id: UUID eines Audits der Kette (beliebige Version).

        Returns:
            Liste aller ``audit_id`` der Kette (inkl. des uebergebenen);
            ``[]`` wenn ``audit_id`` nicht existiert.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT root_audit_id FROM customer_audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return []
            root_id = row[0] or audit_id
            rows = conn.execute(
                "SELECT audit_id FROM customer_audits "
                "WHERE root_audit_id = ? OR audit_id = ?",
                (root_id, audit_id),
            ).fetchall()
        ids = {str(r[0]) for r in rows}
        ids.add(audit_id)
        return sorted(ids)

    def delete(self, audit_id: str) -> bool:
        """Löscht ein Audit samt **ganzer Versionskette**, DSGVO Art. 17).

        Args:
            audit_id: UUID eines Audits der Kette (beliebige Version).

        Returns:
            True wenn mindestens eine Zeile gelöscht wurde, False wenn das Audit
            nicht gefunden wurde.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT root_audit_id FROM customer_audits WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return False
            # Ganze Kette löschen: root_audit_id ist der Ketten-Schlüssel,
            # Fallback auf audit_id für (theoretisch) un-migrierte Zeilen.
            root_id = row[0] or audit_id
            cursor = conn.execute(
                "DELETE FROM customer_audits "
                "WHERE root_audit_id = ? OR audit_id = ?",
                (root_id, audit_id),
            )
            deleted = cursor.rowcount > 0
            geloeschte = cursor.rowcount
        if deleted:
            log.debug(
                "Audit-Kette %s gelöscht (%d Versionen)", root_id[:8], geloeschte
            )
        return deleted

    def delete_version(self, audit_id: str) -> bool:
        """Löscht GENAU diese eine Version (PRIMARY KEY ``audit_id``).

        Andere Versionen derselben Kette (``root_audit_id``) bleiben erhalten.
        War die gelöschte Version die aktuelle (``is_latest=1``), wird die
        neueste verbleibende Version der Kette wieder auf ``is_latest=1``
        gehoben — sonst verschwände der Kunde aus Dashboard/Listen-Filtern
        (die auf ``is_latest=1`` filtern), obwohl noch Versionen existieren.

        Args:
            audit_id: UUID der zu löschenden Einzelversion (PK).

        Returns:
            True wenn die Version existierte und gelöscht wurde, sonst False.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT root_audit_id, is_latest FROM customer_audits "
                "WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return False
            root_id = row[0] or audit_id
            was_latest = bool(row[1])
            conn.execute(
                "DELETE FROM customer_audits WHERE audit_id = ?", (audit_id,)
            )
            if was_latest:
                # Neueste verbleibende Version der Kette wieder aktuell setzen
                # (höchste version, bei Gleichstand jüngstes created_at). Ohne
                # Treffer (letzte Version gelöscht) bleibt nichts zu heben.
                newest = conn.execute(
                    "SELECT audit_id FROM customer_audits "
                    "WHERE root_audit_id = ? OR audit_id = ? "
                    "ORDER BY version DESC, created_at DESC LIMIT 1",
                    (root_id, root_id),
                ).fetchone()
                if newest is not None:
                    conn.execute(
                        "UPDATE customer_audits SET is_latest = 1 "
                        "WHERE audit_id = ?",
                        (newest[0],),
                    )
        log.debug("Audit-Version %s gelöscht", audit_id[:8])
        return True

    def list_summaries(self, limit: int = 50) -> list[dict]:
        """Gibt kompakte Zusammenfassungen aller Audits zurück.

        Args:
            limit: Maximale Anzahl.

        Returns:
            Liste von Dicts mit audit_id, firmenname, created_at,
            overall_score, risk_level sowie ``version`` und ``root_audit_id``
: für Versions-Badge ``v1/v2/v3`` und Ketten-Erkennung in der
            UI). Alle Versionen werden flach gelistet (neueste zuerst).
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT audit_id, firmenname, created_at,
                       overall_score, risk_level, version, root_audit_id
                FROM customer_audits
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "audit_id": row[0],
                "firmenname": row[1],
                "created_at": row[2],
                "overall_score": row[3],
                "risk_level": row[4],
                "version": row[5],
                "root_audit_id": row[6],
            }
            for row in rows
        ]

    def latest_summary_by_subject(self, subject_id: str) -> dict | None:
        """Kompakte Zusammenfassung des jüngsten Audits eines Subjekts-Folge).

        Liest ausschließlich die Score-Spalten (kein ``result_json``-Deserialize)
        für das Dashboard-Surfacing von Kunden-Audit-Scores. Der
        ``subject_id``-Soft-Key wurde in gesetzt; der Index
        ``idx_ca_subject`` deckt diese Abfrage ab. Ein leerer Parameter liefert
        ``None`` — der Default-Leerwert der Spalte (``''``) wird nicht als
        Treffer behandelt.

        Effekt: speist über ``norisk_dashboard/tool.py:_build_customer_audit_loader``
        die ``CustomerAuditCard`` im Dashboard (wenn ein Kunden-Subjekt gewählt
        ist). Eine Änderung der zurückgegebenen Keys bricht dort den Adapter.

        Args:
            subject_id: UUID des kanonischen Subjekts.

        Returns:
            Dict mit ``audit_id``, ``firmenname``, ``created_at``,
            ``overall_score``, ``risk_level`` und ``audit_count`` (Gesamtzahl der
            Audits dieses Subjekts) — oder ``None``, wenn kein Audit existiert.
        """
        if not subject_id:
            return None
        with self._db.connection() as conn:
            # nur die aktuelle Version je Kette (is_latest=1) — sonst
            # surft das Dashboard eine überholte Version. audit_count zählt
            # ebenfalls nur aktuelle Audits (= Anzahl Ketten des Subjekts).
            # Perf (Tier 3): COUNT(*) OVER liefert die Gesamtzahl der Treffer
            # (vor LIMIT) in derselben Query -> ein Scan statt zwei.
            row = conn.execute(
                """
                SELECT audit_id, firmenname, created_at,
                       overall_score, risk_level, COUNT(*) OVER ()
                FROM customer_audits
                WHERE subject_id = ? AND is_latest = 1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (subject_id,),
            ).fetchone()
            if not row:
                return None

        return {
            "audit_id": row[0],
            "firmenname": row[1],
            "created_at": row[2],
            "overall_score": row[3],
            "risk_level": row[4],
            # COUNT(*) OVER = Gesamtzahl der is_latest-Audits des Subjekts
            # (>= 1, da oben bereits ein Row gefunden wurde).
            "audit_count": int(row[5]),
        }
