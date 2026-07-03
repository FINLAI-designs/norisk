"""test_audit_versioning: Audit als neue Version + Doppel-Escape-Fix.

Deckt die Test-Pflichten aus ab (Backend-Schicht, kein GUI):

    * Versions-Roundtrip (neue ID, version+1, supersedes, root, is_latest-Flip)
    * Subjekt-Kontinuität über Versionen
    * Dashboard-Filter (latest_summary_by_subject nur is_latest=1)
    * Ketten-Delete (DSGVO Art. 17)
    * Backfill bleibt unfiltered
    * Abwärtskompatibilität (from_dict ohne neue Felder)
    * Migration normalisiert root_audit_id
    * Escape-Edit-Roundtrip (kein Doppel-Escape via unescape_text)

Pattern: ``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die
customer_audit-DB pro Test (analog test_customer_audit_dashboard_score).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.database import encrypted_db as edb
from tools.customer_audit.application.create_version_use_case import (
    CreateVersionUseCase,
)
from tools.customer_audit.data.customer_audit_repository import (
    CustomerAuditRepository,
)
from tools.customer_audit.domain.entities import (
    AuditMode,
    CustomerAuditResult,
    CustomerData,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    sanitize_text,
    unescape_text,
)
from tools.customer_audit.domain.exceptions import AuditNotFoundError


def _base_audit(
    audit_id: str = "base-1",
    firmenname: str = "Acme GmbH",
    subject_id: str = "subj-1",
) -> CustomerAuditResult:
    """Minimal befülltes Basis-Audit (Wurzel einer künftigen Kette)."""
    return CustomerAuditResult(
        audit_id=audit_id,
        customer_data=CustomerData(firmenname=firmenname),
        infrastructure_data=InfrastructureData(),
        organizational_data=OrganizationalData(),
        network_data=NetworkData(),
        subject_id=subject_id,
        created_at="2026-06-01T10:00:00+00:00",
    )


def _is_latest(repo: CustomerAuditRepository, audit_id: str) -> int:
    with repo._db.connection() as conn:
        row = conn.execute(
            "SELECT is_latest FROM customer_audits WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
    return int(row[0])


class TestVersionRoundtrip:
    def test_create_version_chains_and_flips_is_latest(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            base = _base_audit()
            repo.save(base)

            uc = CreateVersionUseCase(repo)
            v2 = uc.execute(
                "base-1",
                CustomerData(firmenname="Acme GmbH (korrigiert)"),
                InfrastructureData(),
                OrganizationalData(),
                NetworkData(),
            )

            # Neue Identität, Kette korrekt verlinkt
            assert v2.audit_id != "base-1"
            assert v2.version == 2
            assert v2.supersedes_audit_id == "base-1"
            assert v2.root_audit_id == "base-1"

            # is_latest geflippt: Vorgänger 0, neue Version 1
            assert _is_latest(repo, "base-1") == 0
            assert _is_latest(repo, v2.audit_id) == 1

            # Original bleibt unverändert ladbar (Immutabilität)
            original = repo.load_by_id("base-1")
            assert original is not None
            assert original.customer_data.firmenname == "Acme GmbH"
            assert original.version == 1

    def test_subject_id_inherited(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit(subject_id="subj-xyz"))
            v2 = CreateVersionUseCase(repo).execute(
                "base-1",
                CustomerData(firmenname="Acme GmbH"),
                InfrastructureData(),
                OrganizationalData(),
                NetworkData(),
            )
            assert v2.subject_id == "subj-xyz"

    def test_third_version_keeps_root(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit())
            uc = CreateVersionUseCase(repo)
            v2 = uc.execute(
                "base-1", CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            v3 = uc.execute(
                v2.audit_id, CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            assert v3.version == 3
            assert v3.root_audit_id == "base-1"  # Wurzel bleibt
            assert v3.supersedes_audit_id == v2.audit_id
            # Nur v3 ist aktuell
            assert _is_latest(repo, "base-1") == 0
            assert _is_latest(repo, v2.audit_id) == 0
            assert _is_latest(repo, v3.audit_id) == 1

    def test_missing_base_raises(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            with pytest.raises(AuditNotFoundError):
                CreateVersionUseCase(repo).execute(
                    "ghost", CustomerData(firmenname="X"),
                    InfrastructureData(), OrganizationalData(), NetworkData(),
                )


class TestDashboardFilter:
    def test_latest_summary_returns_newest_version_only(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit(subject_id="s1"))
            v2 = CreateVersionUseCase(repo).execute(
                "base-1", CustomerData(firmenname="Acme GmbH"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            summary = repo.latest_summary_by_subject("s1")
            assert summary is not None
            assert summary["audit_id"] == v2.audit_id  # nicht die alte base-1
            # audit_count zählt nur aktuelle Versionen (eine Kette)
            assert summary["audit_count"] == 1


class TestChainDelete:
    def test_delete_removes_whole_chain(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit())
            uc = CreateVersionUseCase(repo)
            v2 = uc.execute(
                "base-1", CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            v3 = uc.execute(
                v2.audit_id, CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            # Löschen über ein mittleres Kettenglied entfernt alle drei
            assert repo.delete(v2.audit_id) is True
            assert repo.load_by_id("base-1") is None
            assert repo.load_by_id(v2.audit_id) is None
            assert repo.load_by_id(v3.audit_id) is None

    def test_delete_unknown_returns_false(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            assert repo.delete("ghost") is False


class TestSingleVersionDelete:
    """I (Live-Test 2026-07-01): delete_version loescht NUR die eine Version;
    die anderen Versionen der Kette bleiben, is_latest wird bei Bedarf auf die
    neueste verbleibende Version umgehaengt (sonst verschwaende der Kunde aus
    dem Dashboard)."""

    def _drei_versionen(self, repo):
        repo.save(_base_audit())
        uc = CreateVersionUseCase(repo)
        v2 = uc.execute(
            "base-1", CustomerData(firmenname="A"),
            InfrastructureData(), OrganizationalData(), NetworkData(),
        )
        v3 = uc.execute(
            v2.audit_id, CustomerData(firmenname="A"),
            InfrastructureData(), OrganizationalData(), NetworkData(),
        )
        return v2, v3

    def test_delete_version_keeps_other_versions(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            v2, v3 = self._drei_versionen(repo)
            # Mittlere Version einzeln loeschen — base-1 und v3 bleiben.
            assert repo.delete_version(v2.audit_id) is True
            assert repo.load_by_id("base-1") is not None
            assert repo.load_by_id(v2.audit_id) is None
            assert repo.load_by_id(v3.audit_id) is not None

    def test_delete_latest_version_rehoists_is_latest(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            v2, v3 = self._drei_versionen(repo)
            assert _is_latest(repo, v3.audit_id) == 1
            # Aktuelle Version loeschen -> v2 wird wieder is_latest=1.
            assert repo.delete_version(v3.audit_id) is True
            assert repo.load_by_id(v3.audit_id) is None
            assert _is_latest(repo, v2.audit_id) == 1
            # Dashboard-Filter findet den Kunden weiterhin (ueber v2).
            summary = repo.latest_summary_by_subject("subj-1")
            assert summary is not None
            assert summary["audit_id"] == v2.audit_id

    def test_delete_non_latest_version_keeps_latest(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            v2, _v3 = self._drei_versionen(repo)
            # base-1 ist NICHT aktuell -> loeschen aendert is_latest nicht.
            assert repo.delete_version("base-1") is True
            assert _is_latest(repo, _v3.audit_id) == 1

    def test_delete_version_unknown_returns_false(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            assert repo.delete_version("ghost") is False


class TestChainNis2Anonymization:
    """P1-Kaskade: delete loescht die ganze Versionskette -> anonymize muss
    ueber ALLE Ketten-audit_ids laufen, sonst bleiben PII von Vorgaenger-
    Versionen verwaist §5)."""

    def test_delete_anonymizes_incidents_of_all_chain_versions(self, tmp_path):
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )
        from tools.customer_audit.application.nis2_incident_service import (
            Nis2IncidentService,
        )
        from tools.customer_audit.domain.nis2_incident import IncidentSeverity

        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit())
            v2 = CreateVersionUseCase(repo).execute(
                "base-1", CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            # Je ein NIS2-Vorfall an der ALTEN (base-1) und der NEUEN Version.
            svc = Nis2IncidentService()
            inc_old = svc.open_incident(
                "base-1", "Max Mustermann Altfall", IncidentSeverity.HIGH,
                description="IBAN-Abfluss alt",
            )
            inc_new = svc.open_incident(
                v2.audit_id, "Hans Meier Neufall", IncidentSeverity.HIGH,
                description="IBAN-Abfluss neu",
            )

            deleted = LoadAuditUseCase(repo).delete(v2.audit_id)
            assert deleted is True

            # BEIDE Incidents anonymisiert (kein verwaister PII-Rest).
            for inc in (inc_old, inc_new):
                reloaded = svc.load_incident(inc.incident_id)
                assert reloaded is not None
                assert reloaded.title == "[anonymisiert]"
                assert reloaded.description == "[anonymisiert]"
                ok, bad = svc.verify_chain(inc.incident_id)
                assert ok is True, f"Kette gebrochen bei {bad}"


class TestBackfillUnfiltered:
    def test_backfill_sees_all_versions(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit())
            CreateVersionUseCase(repo).execute(
                "base-1", CustomerData(firmenname="A"),
                InfrastructureData(), OrganizationalData(), NetworkData(),
            )
            # base-1 ist jetzt is_latest=0 — der-Backfill muss sie trotzdem sehen
            all_audits = repo.load_all_for_backfill()
            assert len(all_audits) == 2


class TestMigration:
    def test_migration_normalizes_root_audit_id(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            with repo._db.connection() as conn:
                conn.execute(
                    "INSERT INTO customer_audits (audit_id, firmenname, "
                    "created_at, overall_score, risk_level, result_json, "
                    "subject_id) VALUES "
                    "('leg-1', 'Alt', '2026-01-01T00:00:00+00:00', 10, 'Hoch', "
                    "'{}', '')"
                )
                # root_audit_id der Legacy-Zeile ist '' (Spalten-Default);
                # Marker entfernen, damit die Migration erneut läuft.
                conn.execute(
                    "DELETE FROM audit_migration_log "
                    "WHERE migration_id = 't306_audit_versioning_v1'"
                )
            repo._migrate_versioning()
            with repo._db.connection() as conn:
                row = conn.execute(
                    "SELECT root_audit_id FROM customer_audits "
                    "WHERE audit_id = 'leg-1'"
                ).fetchone()
            assert row[0] == "leg-1"


class TestBackwardCompat:
    def test_from_dict_without_version_fields(self):
        result = CustomerAuditResult.from_dict(
            {"audit_id": "x", "customer_data": {"firmenname": "Acme"}}
        )
        assert result.version == 1
        assert result.supersedes_audit_id == ""
        assert result.root_audit_id == ""

    def test_to_from_dict_roundtrip_with_version(self):
        src = CustomerAuditResult(
            audit_id="a",
            customer_data=CustomerData(firmenname="Acme"),
            infrastructure_data=InfrastructureData(),
            organizational_data=OrganizationalData(),
            network_data=NetworkData(),
            version=3,
            supersedes_audit_id="b",
            root_audit_id="root",
        )
        again = CustomerAuditResult.from_dict(src.to_dict())
        assert again.version == 3
        assert again.supersedes_audit_id == "b"
        assert again.root_audit_id == "root"


class TestEscapeEditRoundtrip:
    """/: Persist ist Klartext — Edit-Roundtrip ist Identität.

    Der frühere-Unescape-beim-Laden ist entfallen; ``unescape_text``
    existiert nur noch für die einmalige Daten-Migration.
    """

    def test_edit_resave_ist_byteidentisch(self):
        raw = "Müller & Co. <AG> \"q\" 'z'"
        persisted = sanitize_text(raw)
        # Edit-Laden ohne Unescape, erneut speichern: Identität, nie Entities.
        re_persisted = sanitize_text(persisted)
        assert re_persisted == persisted == raw
        assert "&amp;" not in re_persisted

    def test_literal_entity_eingabe_bleibt_erhalten(self):
        # Ein User darf literal "&amp;" eintippen — frueher haette der
        # Unescape das beim Edit-Laden zu "&" zerstoert.
        raw = "Encoding-Doku: &amp; bleibt &amp;"
        assert sanitize_text(raw) == raw

    def test_unescape_text_ist_inverse_des_altformats(self):
        # Migrations-Hilfe: ent-escaped das Alt-Persist-Format exakt;
        # entity-freie Strings sind ein No-op.
        persisted_alt = "A &amp; B &lt;x&gt; &quot;q&quot; &#x27;z&#x27;"
        assert unescape_text(persisted_alt) == "A & B <x> \"q\" 'z'"
        assert unescape_text("Musterfirma GmbH") == "Musterfirma GmbH"


class TestSubjectPropagation:
    def test_customer_version_propagates_stammdaten(self, tmp_path):
        #/P2: editierte Stammdaten werden ins bestehende Subjekt
        # nachgezogen (subject_id NICHT neu aufgelöst — Ketten-Stabilität).
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit(subject_id="s1"))
            store = MagicMock()
            CreateVersionUseCase(repo, subject_store=store).execute(
                "base-1",
                CustomerData(
                    firmenname="Acme GmbH",
                    branche="Finanzen",
                    unternehmensgroesse="51-250",
                ),
                InfrastructureData(),
                OrganizationalData(),
                NetworkData(),
                audit_mode=AuditMode.CUSTOMER,
            )
            store.update_stammdaten.assert_called_once()
            _args, kwargs = store.update_stammdaten.call_args
            assert kwargs["branche"] == "Finanzen"
            assert kwargs["groesse"] == "51-250"

    def test_self_version_does_not_propagate(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = CustomerAuditRepository()
            repo.save(_base_audit(subject_id="s1"))
            store = MagicMock()
            CreateVersionUseCase(repo, subject_store=store).execute(
                "base-1",
                CustomerData(firmenname="Mein System"),
                InfrastructureData(),
                OrganizationalData(),
                NetworkData(),
                audit_mode=AuditMode.SELF,
            )
            store.update_stammdaten.assert_not_called()
