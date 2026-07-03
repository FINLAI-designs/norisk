"""test_t315_escape_at_render/: escape-at-render.

Deckt die Test-Pflichten aus ab (Backend-Schicht, kein GUI):

    * ``core.escape.escape_html`` — Zeichenmenge, bewusst nicht idempotent
    * Daten-Migration ``t315_escape_at_render_v1`` gegen simulierte Alt-DB
      (Fixtures 1–7 aus dem T315_ESCAPE_MIGRATION_TEST_PLAN)
    * Subjekt-Namen-Backfill ``t315_unescape_profile_names_v1``
      (security_scoring, Review-Nachtrag — Dedup-Schutz)
    * PDF-Report robust gegen rohe Markup-Zeichen in Freitexten
    * JSON-Export enthält Klartext

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die
customer_audit-DB pro Test (analog test_audit_versioning).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from unittest.mock import patch

from core import escape as core_escape
from core.database import encrypted_db as edb
from tools.customer_audit.data.customer_audit_repository import (
    _SCHEMA,
    _UNESCAPE_MIGRATION_ID,
    CustomerAuditRepository,
)
from tools.customer_audit.data.report_generator import CustomerReportGenerator
from tools.customer_audit.domain.entities import (
    CustomerAuditResult,
    CustomerData,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
)

# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

_RAW_FIRMA = 'Müller & Co. <AG> "Wien"'


def _alt_escape(value: str) -> str:
    """Repliziert das Alt-Persist-Escaping (sanitize_text vor)."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _alt_escape_strings(obj):  # noqa: ANN001, ANN201
    """Escaped rekursiv alle Strings (Alt-Zustand der gesamten Payload)."""
    if isinstance(obj, dict):
        return {k: _alt_escape_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_alt_escape_strings(x) for x in obj]
    if isinstance(obj, str):
        return _alt_escape(obj)
    return obj


def _audit(audit_id: str = "alt-1", firmenname: str = _RAW_FIRMA) -> CustomerAuditResult:
    return CustomerAuditResult(
        audit_id=audit_id,
        customer_data=CustomerData(firmenname=firmenname),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        created_at="2026-06-01T10:00:00+00:00",
    )


def _seed_alt_row(
    conn,  # noqa: ANN001
    audit_id: str,
    *,
    payload_json: str | None = None,
) -> None:
    """Schreibt eine Zeile im Alt-Format (escaped) direkt in die DB."""
    if payload_json is None:
        payload = _alt_escape_strings(_audit(audit_id).to_dict())
        payload_json = json.dumps(payload, ensure_ascii=False)
    conn.execute(
        "INSERT INTO customer_audits "
        "(audit_id, firmenname, created_at, overall_score, risk_level, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            audit_id,
            _alt_escape(_RAW_FIRMA),
            "2026-06-01T10:00:00+00:00",
            77.0,
            "Mittel",
            payload_json,
        ),
    )


def _make_alt_db() -> None:
    """Erzeugt die simulierte Alt-DB (Schema ohne neue Migrations-Marker)."""
    db = edb.EncryptedDatabase("customer_audit")
    with db.connection() as conn:
        conn.executescript(_SCHEMA)


def _firmenname_spalte(repo: CustomerAuditRepository, audit_id: str) -> str:
    with repo._db.connection() as conn:  # noqa: SLF001
        row = conn.execute(
            "SELECT firmenname FROM customer_audits WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# core.escape.escape_html
# ---------------------------------------------------------------------------


class TestEscapeHtml:
    def test_zeichenmenge(self):
        assert (
            core_escape.escape_html("a & b <x> \"q\" 'z'")
            == "a &amp; b &lt;x&gt; &quot;q&quot; &#x27;z&#x27;"
        )

    def test_bewusst_nicht_idempotent(self):
        # Doppeltes Escapen soll SICHTBAR werden, nicht versteckt.
        once = core_escape.escape_html("a & b")
        assert core_escape.escape_html(once) != once

    def test_non_string_wird_konvertiert(self):
        assert core_escape.escape_html(42) == "42"


# ---------------------------------------------------------------------------
# Migration t315_escape_at_render_v1
# ---------------------------------------------------------------------------


class TestUnescapeMigration:
    def test_alt_db_wird_klartext(self, tmp_path):
        """Fixture 1: escaped Bestandszeilen werden Klartext, Marker gesetzt."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(conn, "alt-1")

            repo = CustomerAuditRepository()
            geladen = repo.load_by_id("alt-1")
            assert geladen is not None
            assert geladen.customer_data.firmenname == _RAW_FIRMA
            assert _firmenname_spalte(repo, "alt-1") == _RAW_FIRMA
            with repo._db.connection() as conn:  # noqa: SLF001
                marker = conn.execute(
                    "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                    (_UNESCAPE_MIGRATION_ID,),
                ).fetchone()
            assert marker is not None

    def test_frische_db_setzt_marker_ohne_fehler(self, tmp_path):
        """Fixture 2: leere DB — Migration läuft leer durch."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            with repo._db.connection() as conn:  # noqa: SLF001
                marker = conn.execute(
                    "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                    (_UNESCAPE_MIGRATION_ID,),
                ).fetchone()
            assert marker is not None

    def test_doppellauf_aendert_nichts(self, tmp_path):
        """Fixture 3: zweiter Lauf ist No-op — Literal-Entities überleben."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(conn, "alt-1")
            CustomerAuditRepository()

            # Nach der Migration tippt ein User literal '&amp;' (Klartext-Ära)
            literal = "Encoding-Doku: &amp; bleibt"
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                conn.execute(
                    "UPDATE customer_audits SET firmenname = ? WHERE audit_id = ?",
                    (literal, "alt-1"),
                )

            repo2 = CustomerAuditRepository()  # zweiter Init — Marker greift
            assert _firmenname_spalte(repo2, "alt-1") == literal

    def test_korrupte_zeile_wird_uebersprungen(self, tmp_path):
        """Fixture 5: invalides JSON crasht den Start nicht; Rest migriert."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(conn, "alt-ok")
                _seed_alt_row(conn, "alt-kaputt", payload_json="{invalid json")

            repo = CustomerAuditRepository()
            assert _firmenname_spalte(repo, "alt-ok") == _RAW_FIRMA
            with repo._db.connection() as conn:  # noqa: SLF001
                marker = conn.execute(
                    "SELECT 1 FROM audit_migration_log WHERE migration_id = ?",
                    (_UNESCAPE_MIGRATION_ID,),
                ).fetchone()
            assert marker is not None

    def test_nach_migration_roundtrip_klartext(self, tmp_path):
        """Fixture 7: Save→Load nach Migration ist byte-identischer Klartext."""
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_audit("neu-1"))
            geladen = repo.load_by_id("neu-1")
            assert geladen is not None
            assert geladen.customer_data.firmenname == _RAW_FIRMA
            assert "&amp;" not in json.dumps(geladen.to_dict())

    def test_versions_kette_wird_migriert_versionsfelder_unangetastet(
        self, tmp_path
    ):
        """Fixture 4: v1+v2 einer-Kette werden Klartext; version/
        supersedes/root_audit_id/is_latest bleiben unverändert."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(conn, "kette-v1")
                _seed_alt_row(conn, "kette-v2")
                # Spalten existieren in der Alt-DB noch nicht — sie
                # kommen via ensure_column beim Repo-Init. Kette danach setzen.
            repo = CustomerAuditRepository()
            with repo._db.connection() as conn:  # noqa: SLF001
                conn.execute(
                    "UPDATE customer_audits SET version=2, "
                    "supersedes_audit_id='kette-v1', root_audit_id='kette-v1', "
                    "is_latest=1 WHERE audit_id='kette-v2'"
                )
                conn.execute(
                    "UPDATE customer_audits SET is_latest=0, "
                    "root_audit_id='kette-v1' WHERE audit_id='kette-v1'"
                )
                # Migration erneut erzwingen (Marker entfernen), um die
                # Kette im Alt-Zustand zu migrieren.
                conn.execute(
                    "DELETE FROM audit_migration_log WHERE migration_id = ?",
                    (_UNESCAPE_MIGRATION_ID,),
                )
                conn.execute(
                    "UPDATE customer_audits SET firmenname = ?",
                    ("Acme &amp; Partner",),
                )
            repo2 = CustomerAuditRepository()
            with repo2._db.connection() as conn:  # noqa: SLF001
                rows = conn.execute(
                    "SELECT audit_id, firmenname, version, supersedes_audit_id, "
                    "root_audit_id, is_latest FROM customer_audits "
                    "ORDER BY audit_id"
                ).fetchall()
            assert [r[1] for r in rows] == ["Acme & Partner", "Acme & Partner"]
            assert rows[0][2:] == (1, "", "kette-v1", 0)
            assert rows[1][2:] == (2, "kette-v1", "kette-v1", 1)

    def test_fixture6_literal_entity_in_nie_escaptem_string(self, tmp_path):
        """Fixture 6 (dokumentierte ADR-Kante): ein NIE escapter String mit
        literalem '&amp;' (z.B. Scan-Evidence) kollabiert beim Erstlauf zu
        '&' — bewusst akzeptiert (Altdaten = Testdaten)."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            payload = _audit("kante-1").to_dict()
            payload["sovereignty_audit"]["scan_errors"] = [
                "DNS-TXT enthielt literal &amp; (nie escaped)"
            ]
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(
                    conn,
                    "kante-1",
                    payload_json=json.dumps(payload, ensure_ascii=False),
                )
            repo = CustomerAuditRepository()
            geladen = repo.load_by_id("kante-1")
            assert geladen is not None
            assert geladen.sovereignty_audit.scan_errors == [
                "DNS-TXT enthielt literal & (nie escaped)"
            ]

    def test_korrupte_zeile_firmenname_wird_trotzdem_migriert(self, tmp_path):
        """Review-Fix: die denormalisierte Spalte hängt nicht am Payload."""
        with patch.object(edb, "DB_DIR", tmp_path):
            _make_alt_db()
            db = edb.EncryptedDatabase("customer_audit")
            with db.connection() as conn:
                _seed_alt_row(conn, "alt-kaputt", payload_json="{invalid json")
            repo = CustomerAuditRepository()
            assert _firmenname_spalte(repo, "alt-kaputt") == _RAW_FIRMA


class TestProfileNamesBackfill:
    """Review-Nachtrag: Subjekt-Namen (system_profiles) werden ent-escaped."""

    def test_profilnamen_werden_klartext(self, tmp_path):
        from tools.security_scoring.data.tech_stack_repository import (
            TechStackRepository,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = TechStackRepository()
            literal = "Doku: &amp; bleibt"
            with repo._db.connection() as conn:  # noqa: SLF001
                conn.execute(
                    "INSERT INTO system_profiles "
                    "(profile_id, name, system_type, created_at, updated_at) "
                    "VALUES ('p1', ?, 'client', 't', 't')",
                    ("Müller &amp; Co. &lt;AG&gt;",),
                )
                # Marker zurücksetzen, um den Backfill auf den Alt-Datensatz
                # anzuwenden (erster Init lief auf leerer Tabelle).
                conn.execute("DELETE FROM profile_migration_log")
            repo2 = TechStackRepository()
            with repo2._db.connection() as conn:  # noqa: SLF001
                name = conn.execute(
                    "SELECT name FROM system_profiles WHERE profile_id='p1'"
                ).fetchone()[0]
            assert name == "Müller & Co. <AG>"

            # Doppellauf-Schutz: ein NACH der Migration getipptes Literal
            # überlebt den nächsten Init (Marker greift).
            with repo2._db.connection() as conn:  # noqa: SLF001
                conn.execute(
                    "UPDATE system_profiles SET name = ? WHERE profile_id='p1'",
                    (literal,),
                )
            repo3 = TechStackRepository()
            with repo3._db.connection() as conn:  # noqa: SLF001
                name = conn.execute(
                    "SELECT name FROM system_profiles WHERE profile_id='p1'"
                ).fetchone()[0]
            assert name == literal


# ---------------------------------------------------------------------------
# Export-Pfade
# ---------------------------------------------------------------------------


class TestExportRobust:
    def test_pdf_report_crasht_nicht_bei_rohem_markup(self, tmp_path):
        """ReportLab-Paragraph bekommt nur escapte Werte — kein Parse-Error."""
        result = _audit("pdf-1", firmenname='A<b & "c"> GmbH')
        out = tmp_path / "report.pdf"
        CustomerReportGenerator().generate(result, out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_json_export_enthaelt_klartext(self):
        data = _audit("json-1").to_dict()
        text = json.dumps(data, ensure_ascii=False)
        assert "Müller & Co." in text
        assert "&amp;" not in text
