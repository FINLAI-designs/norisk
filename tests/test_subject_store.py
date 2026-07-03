"""test_subject_store — Tests für die kanonische Subjekt-Entität.

Deckt:
    * core-Modell:class:`Subject` (Properties is_own_system/display_name,
      Kind-Werte byte-identisch zu SystemType).
    *:class:`ScoringSubjectStore` (Adapter über ManageProfilesUseCase):
      - ensure_self_subject: legt genau ein eigenes Subjekt an, idempotent.
      - find_or_create_client: Dedup per Name (case-insensitive, kind-gefiltert).
      - get / get_self / list_all (eigenes zuerst).
      - Protocol-Konformität gegen den core-Port.
      - Reuse: ein über ManageProfilesUseCase angelegtes Kundenprofil ist als
        Subjekt lesbar (gemeinsame system_profiles-Tabelle, kein Parallelpfad).

Pattern wie ``test_hardening_score_repository``:
``with patch.object(edb, "DB_DIR", tmp_path):`` isoliert die DB pro Test.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.database import encrypted_db as edb
from core.security_subject.models import Subject, SubjectKind
from core.security_subject.ports import SubjectStore
from tools.security_scoring.application.subject_store import (
    create_default_subject_store,
)

# ---------------------------------------------------------------------------
# core-Modell
# ---------------------------------------------------------------------------


class TestSubjectModel:
    def test_self_subject_is_own_system(self):
        s = Subject(subject_id="1", kind=SubjectKind.EIGENES, name="Mein System")
        assert s.is_own_system is True
        assert s.display_name == "Mein System (Eigenes System)"

    def test_client_subject_display_name_plain(self):
        s = Subject(subject_id="2", kind=SubjectKind.KUNDE, name="Muster GmbH")
        assert s.is_own_system is False
        assert s.display_name == "Muster GmbH"

    def test_kind_values_match_system_type(self):
        assert SubjectKind.EIGENES.value == "eigenes"
        assert SubjectKind.KUNDE.value == "kunde"


# ---------------------------------------------------------------------------
# SubjectStore — eigenes Subjekt
# ---------------------------------------------------------------------------


class TestEnsureSelf:
    def test_ensure_self_creates_single_subject(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            subject = store.ensure_self_subject("Mein System")
            assert subject.kind is SubjectKind.EIGENES
            assert subject.name == "Mein System"
            assert store.get_self() is not None

    def test_ensure_self_is_idempotent(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            first = store.ensure_self_subject("Mein System")
            second = store.ensure_self_subject("Anderer Name")
            assert second.subject_id == first.subject_id
            assert len([s for s in store.list_all() if s.is_own_system]) == 1


# ---------------------------------------------------------------------------
# SubjectStore — Kunden-Subjekt
# ---------------------------------------------------------------------------


class TestFindOrCreateClient:
    def test_create_then_find_same(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            created = store.find_or_create_client("Muster GmbH")
            again = store.find_or_create_client("Muster GmbH")
            assert created.subject_id == again.subject_id
            assert created.kind is SubjectKind.KUNDE

    def test_dedup_is_case_insensitive(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            a = store.find_or_create_client("Muster GmbH")
            b = store.find_or_create_client("muster gmbh")
            assert a.subject_id == b.subject_id

    def test_client_name_collision_with_self_creates_client(self, tmp_path):
        # Gleicher Name wie eigenes System darf kein eigenes Subjekt liefern;
        # wiederholter Aufruf bleibt dedupliziert (kind-gefilterter Lookup).
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("ACME")
            client = store.find_or_create_client("ACME")
            client_again = store.find_or_create_client("ACME")
            assert client.subject_id != own.subject_id
            assert client.kind is SubjectKind.KUNDE
            assert client_again.subject_id == client.subject_id


# ---------------------------------------------------------------------------
# SubjectStore — Listing
# ---------------------------------------------------------------------------


class TestListing:
    def test_list_all_own_system_first_then_alphabetical(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            store.find_or_create_client("Zeta GmbH")
            store.ensure_self_subject("Mein System")
            store.find_or_create_client("Alpha AG")
            all_subjects = store.list_all()
            assert all_subjects[0].is_own_system is True
            client_names = [s.name for s in all_subjects if not s.is_own_system]
            assert client_names == ["Alpha AG", "Zeta GmbH"]

    def test_get_unknown_returns_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            assert store.get("does-not-exist") is None


# ---------------------------------------------------------------------------
# Port-Konformität
# ---------------------------------------------------------------------------


class TestPortConformance:
    def test_store_satisfies_subjectstore_protocol(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert isinstance(store, SubjectStore)


# ---------------------------------------------------------------------------
# Reuse statt Parallelpfad
# ---------------------------------------------------------------------------


class TestUpdateStammdaten:
    def test_update_persists_branche_and_groesse(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            c = store.find_or_create_client("Muster GmbH")
            store.update_stammdaten(
                c.subject_id, branche="IT-Dienstleistung", groesse="11-50"
            )
            reread = store.get(c.subject_id)
            assert reread is not None
            assert reread.branche == "IT-Dienstleistung"
            assert reread.groesse == "11-50"

    def test_update_only_set_fields(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            c = store.find_or_create_client("Muster GmbH")
            store.update_stammdaten(c.subject_id, branche="Kanzlei")
            store.update_stammdaten(c.subject_id, contact="Frau Muster")
            reread = store.get(c.subject_id)
            assert reread is not None
            assert reread.branche == "Kanzlei"  # bleibt erhalten
            assert reread.contact == "Frau Muster"

    def test_update_unknown_subject_is_noop(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            store.update_stammdaten("does-not-exist", branche="X")  # kein Crash


class TestUpdateScopingProfile:
    """: NIS2-taugliche Scoping-Felder des eigenen Subjekts."""

    def test_update_persists_scoping_fields(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_scoping_profile(
                own.subject_id,
                fte=42,
                umsatz_eur=5_000_000,
                bilanzsumme_eur=3_000_000,
                sektor_key="bankwesen",
                rolle="IT-Leitung / IT-Verantwortung",
            )
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.fte == 42
            assert reread.umsatz_eur == 5_000_000
            assert reread.bilanzsumme_eur == 3_000_000
            assert reread.sektor_key == "bankwesen"
            assert reread.nis2_anhang == "I"  # aus sektor_key abgeleitet (Adapter)
            assert reread.rolle == "IT-Leitung / IT-Verantwortung"

    def test_anhang_resyncs_when_sektor_changes(self, tmp_path):
        # Regression: der denormalisierte Anhang darf nicht „stale" bleiben,
        # wenn der Sektor auf einen Nicht-NIS2-Sektor gewechselt wird.
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_scoping_profile(own.subject_id, sektor_key="bankwesen")
            assert store.get(own.subject_id).nis2_anhang == "I"
            store.update_scoping_profile(own.subject_id, sektor_key="keiner")
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.sektor_key == "keiner"
            assert reread.nis2_anhang == ""  # resynced, nicht stale "I"

    def test_scoping_only_set_fields_preserved(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_scoping_profile(own.subject_id, sektor_key="gesundheit")
            store.update_scoping_profile(own.subject_id, fte=7)
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.sektor_key == "gesundheit"  # bleibt erhalten
            assert reread.fte == 7

    def test_scoping_defaults_are_none_and_empty(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.fte is None
            assert reread.umsatz_eur is None
            assert reread.sektor_key == ""
            assert reread.nis2_anhang == ""

    def test_scoping_unknown_subject_is_noop(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            store.update_scoping_profile("does-not-exist", fte=5)  # kein Crash


class TestUpdateProfileW1:
    """: W1-Interview-Profilfelder (segment + Infrastruktur-Flags)."""

    def test_update_persists_w1_fields(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_profile_w1(
                own.subject_id,
                segment="epu",
                hat_eigene_website=1,
                hat_eigene_api=0,
                ist_entwickler=1,
                hat_server_infrastruktur=0,
            )
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.segment == "epu"
            assert reread.hat_eigene_website == 1
            assert reread.hat_eigene_api == 0  # 0 bleibt 0
            assert reread.ist_entwickler == 1
            assert reread.hat_server_infrastruktur == 0

    def test_w1_defaults_are_empty_and_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.segment == ""
            assert reread.hat_eigene_website is None
            assert reread.hat_eigene_api is None
            assert reread.ist_entwickler is None
            assert reread.hat_server_infrastruktur is None

    def test_w1_unset_field_preserved_via_sentinel(self, tmp_path):
        # Zwei Teil-Updates: das beim zweiten Aufruf NICHT übergebene Flag bleibt
        # erhalten (Sentinel-Semantik, kein Voll-Zeilen-Clobbering).
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_profile_w1(own.subject_id, hat_eigene_api=1)
            store.update_profile_w1(own.subject_id, segment="kmu_klein")
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.hat_eigene_api == 1  # bleibt erhalten
            assert reread.segment == "kmu_klein"

    def test_w1_none_resets_field_not_unchanged(self, tmp_path):
        # Kern der Sentinel-Wahl: explizites None setzt das Flag auf „nicht
        # erfasst" zurück (≠ unverändert). Würde None als Unverändert-Marker
        # dienen, bliebe der Wert fälschlich 1.
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_profile_w1(own.subject_id, hat_eigene_api=1)
            assert store.get(own.subject_id).hat_eigene_api == 1
            store.update_profile_w1(own.subject_id, hat_eigene_api=None)
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.hat_eigene_api is None  # zurückgesetzt, nicht 1

    def test_w1_zero_distinct_from_none(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_profile_w1(own.subject_id, hat_eigene_website=0)
            reread = store.get(own.subject_id)
            assert reread is not None
            assert reread.hat_eigene_website == 0  # 0, nicht None

    def test_w1_unknown_subject_is_noop(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            store.update_profile_w1("does-not-exist", segment="epu")  # kein Crash

    def test_w1_invalid_segment_raises(self, tmp_path):
        # ungueltiger Segment-Wert -> fail-closed ValueError (vor DB-Zugriff).
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            with pytest.raises(ValueError, match="Ungueltiges Segment"):
                store.update_profile_w1(own.subject_id, segment="bloedsinn")

    def test_w1_alle_enum_segmente_akzeptiert(self, tmp_path):
        from core.security_subject.w1_profil import Segment

        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            for seg in Segment:
                store.update_profile_w1(own.subject_id, segment=seg.value)
                assert store.get(own.subject_id).segment == seg.value

    def test_w1_leeres_segment_akzeptiert(self, tmp_path):
        # "" = nicht erfasst ist ein gueltiger Wert (kein "unveraendert"-None).
        with patch.object(edb, "DB_DIR", tmp_path):
            store = create_default_subject_store()
            assert store is not None
            own = store.ensure_self_subject("Mein System")
            store.update_profile_w1(own.subject_id, segment="epu")
            store.update_profile_w1(own.subject_id, segment="")
            assert store.get(own.subject_id).segment == ""


class TestReusesProfileStore:
    def test_profile_created_via_use_case_is_readable_as_subject(self, tmp_path):
        from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (  # noqa: E501
            create_default_manage_profiles_use_case,
        )

        with patch.object(edb, "DB_DIR", tmp_path):
            uc = create_default_manage_profiles_use_case()
            assert uc is not None
            profile = uc.create_customer_profile("Beispiel GmbH", contact="Frau Muster")

            store = create_default_subject_store()
            assert store is not None
            subject = store.get(profile.id)
            assert subject is not None
            assert subject.name == "Beispiel GmbH"
            assert subject.kind is SubjectKind.KUNDE
            assert subject.contact == "Frau Muster"
