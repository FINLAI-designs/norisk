"""test_scoping_profile — Persistenz- und Mapping-Tests fürs Einstiegs-Scoping.

Deckt:
    * ``core.security_subject.scoping_constants.anhang_fuer`` (reines Mapping).
    * Additive, idempotente ``system_profiles``-Migration (neue Spalten).
    * Roundtrip der neuen Felder über das Repository.
    * Abwärtskompatibilität von ``_row_to_profile`` bei kürzeren (alten) Zeilen.

DB-Isolation wie ``test_subject_store``:
``with patch.object(edb, "DB_DIR", tmp_path):``.
"""

from __future__ import annotations

from unittest.mock import patch

from core.database import encrypted_db as edb
from core.security_subject.scoping_constants import (
    ANHANG_I,
    ANHANG_II,
    SEKTOREN,
    anhang_fuer,
)
from tools.security_scoring.data.tech_stack_repository import (
    TechStackRepository,
    _row_to_profile,
)
from tools.security_scoring.domain.tech_stack.entities import SystemProfile
from tools.security_scoring.domain.tech_stack.enums import SystemType

# ---------------------------------------------------------------------------
# Anhang-Mapping (rein, keine I/O)
# ---------------------------------------------------------------------------


class TestAnhangMapping:
    def test_anhang_fuer_matches_each_sector(self):
        for sektor in SEKTOREN:
            assert anhang_fuer(sektor.key) == sektor.anhang

    def test_anhang_fuer_unknown_returns_empty(self):
        assert anhang_fuer("gibtsnicht") == ""
        assert anhang_fuer("") == ""

    def test_sector_keys_unique(self):
        keys = [s.key for s in SEKTOREN]
        assert len(keys) == len(set(keys))

    def test_anhang_values_valid(self):
        for sektor in SEKTOREN:
            assert sektor.anhang in (ANHANG_I, ANHANG_II, "")

    def test_both_anhaenge_present(self):
        anhaenge = {s.anhang for s in SEKTOREN}
        assert ANHANG_I in anhaenge
        assert ANHANG_II in anhaenge


# ---------------------------------------------------------------------------
# Migration + Roundtrip
# ---------------------------------------------------------------------------


class TestMigration:
    def test_ensure_table_idempotent(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            TechStackRepository()  # 1. Lauf: legt additive Spalten an
            TechStackRepository()  # 2. Lauf: darf nicht werfen (Spalten existieren)

    def test_scoping_fields_roundtrip(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = TechStackRepository()
            repo.create(
                SystemProfile(
                    id="s1",
                    name="Mein System",
                    system_type=SystemType.EIGENES,
                    fte=10,
                    umsatz_eur=1_000_000,
                    sektor_key="chemie",
                    nis2_anhang="II",
                    rolle="Geschäftsführung / Inhaber:in",
                    created_at="t",
                    updated_at="t",
                )
            )
            loaded = repo.get_by_id("s1")
            assert loaded is not None
            assert loaded.fte == 10
            assert loaded.umsatz_eur == 1_000_000
            assert loaded.sektor_key == "chemie"
            assert loaded.nis2_anhang == "II"
            assert loaded.rolle == "Geschäftsführung / Inhaber:in"
            assert loaded.bilanzsumme_eur is None  # nicht gesetzt → bleibt NULL

    def test_update_sets_scoping_columns(self, tmp_path):
        with patch.object(edb, "DB_DIR", tmp_path):
            repo = TechStackRepository()
            repo.create(
                SystemProfile(
                    id="s2",
                    name="X",
                    system_type=SystemType.EIGENES,
                    created_at="t",
                    updated_at="t",
                )
            )
            base = repo.get_by_id("s2")
            assert base is not None
            from dataclasses import replace

            repo.update(replace(base, fte=3, sektor_key="forschung", nis2_anhang="II"))
            loaded = repo.get_by_id("s2")
            assert loaded is not None
            assert loaded.fte == 3
            assert loaded.sektor_key == "forschung"


# ---------------------------------------------------------------------------
# Abwärtskompatibilität
# ---------------------------------------------------------------------------


class TestRowCompat:
    def test_short_row_defaults_new_fields(self):
        # Alte 8-Spalten-Zeile (vor/) → neue Felder defaulten sauber.
        short = ("id", "Name", "eigenes", "", "", "{}", "t", "t")
        profile = _row_to_profile(short)
        assert profile.branche == ""
        assert profile.fte is None
        assert profile.umsatz_eur is None
        assert profile.sektor_key == ""
        assert profile.nis2_anhang == ""
        assert profile.rolle == ""
