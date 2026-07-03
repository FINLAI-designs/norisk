"""test_db_isolation — Tests für strikte DB-Pfad-Isolation per app_id.

Stellt sicher dass:
1. Ohne Kontext: DB_DIR-Root (nur in Tests ohne App-Boot relevant)
2. Mit Kontext: App-spezifischer Pfad ~/.finlai/db/<app_id>/<db>.db
3. Verschiedene app_ids → verschiedene Pfade → keine Cross-Contamination
4. clear_db_app_id → Kontext zurückgesetzt → DB_DIR-Root
5. Eine Datei im DB_DIR-Root wird NICHT automatisch von App-Kontexten
   gelesen (kein Legacy-Backward-Compat-Fallback mehr — bewusste
   Entfernung zur Vermeidung App-übergreifender Datenkontamination).

Hinweis: Diese Tests verwenden tmp_path und patchen DB_DIR —
kein Schreiben in das echte ~/.finlai/db/.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import (
    clear_db_app_id,
    get_db_app_id,
    set_db_app_id,
)
from core.database.encrypted_db import _get_db_dir_for_name

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_context():
    """Setzt den DB-Kontext vor und nach jedem Test zurück."""
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def fake_db_dir(tmp_path: Path):
    """Ersetzt DB_DIR durch ein temporäres Verzeichnis."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


# ---------------------------------------------------------------------------
# db_context Tests
# ---------------------------------------------------------------------------


class TestDbContext:
    """Tests für core/database/db_context.py."""

    def test_initial_context_is_none(self):
        """Ohne set_db_app_id ist der Kontext None."""
        assert get_db_app_id() is None

    def test_set_and_get_context(self):
        """set_db_app_id setzt, get_db_app_id liest."""
        set_db_app_id("teachme")
        assert get_db_app_id() == "teachme"

    def test_clear_resets_to_none(self):
        """clear_db_app_id setzt Kontext auf None zurück."""
        set_db_app_id("norisk")
        clear_db_app_id()
        assert get_db_app_id() is None

    def test_overwrite_context(self):
        """set_db_app_id überschreibt vorherigen Wert."""
        set_db_app_id("finlai")
        set_db_app_id("teachme_buchhaltung_free")
        assert get_db_app_id() == "teachme_buchhaltung_free"


# ---------------------------------------------------------------------------
# DB-Pfad-Isolation Tests
# ---------------------------------------------------------------------------


class TestDbPathIsolation:
    """Tests für _get_db_dir_for_name und EncryptedDatabase-Pfad-Logik."""

    def test_kein_kontext_ergibt_root(self, fake_db_dir: Path):
        """Ohne Kontext: DB_DIR-Root (Tests ohne App-Boot)."""
        resolved = _get_db_dir_for_name("teachings")
        assert resolved == fake_db_dir

    def test_kontext_ergibt_subdir(self, fake_db_dir: Path):
        """Mit Kontext: DB_DIR/<app_id>/."""
        set_db_app_id("teachme")
        resolved = _get_db_dir_for_name("teachings")
        assert resolved == fake_db_dir / "teachme"

    def test_kunde_ergibt_eigenes_subdir(self, fake_db_dir: Path):
        """teachMe Accounting bekommt eigenes Verzeichnis."""
        set_db_app_id("teachme_buchhaltung_free")
        resolved = _get_db_dir_for_name("teachings")
        assert resolved == fake_db_dir / "teachme_buchhaltung_free"

    def test_verschiedene_app_ids_verschiedene_verzeichnisse(self, fake_db_dir: Path):
        """teachme und teachme_buchhaltung_free haben VERSCHIEDENE DB-Pfade."""
        set_db_app_id("teachme")
        pfad_teachme = _get_db_dir_for_name("teachme_cheatsheet")

        set_db_app_id("teachme_buchhaltung_free")
        pfad_buchhalter = _get_db_dir_for_name("teachme_cheatsheet")

        assert pfad_teachme != pfad_buchhalter
        assert pfad_teachme == fake_db_dir / "teachme"
        assert pfad_buchhalter == fake_db_dir / "teachme_buchhaltung_free"

    def test_root_datei_wird_von_app_kontext_ignoriert(self, fake_db_dir: Path):
        """Datei im DB_DIR-Root darf NICHT vom App-Kontext gelesen werden.

        Früher existierte ein Backward-Compat-Fallback: Wenn ``teachings.db``
        im Root lag und im App-Subdir fehlte, wurde der Root-Pfad benutzt.
        Dieses Verhalten wurde entfernt — es führte zu App-übergreifender
        Datenkontamination auf Entwickler-Maschinen.
        """
        root_file = fake_db_dir / "teachings.db"
        root_file.touch()

        set_db_app_id("teachme")
        resolved = _get_db_dir_for_name("teachings")

        assert resolved == fake_db_dir / "teachme"
        assert resolved != fake_db_dir

    def test_basis_apps_bekommen_eigenes_subdir_ohne_fallback(self, fake_db_dir: Path):
        """finlai/norisk/automate/teachme haben keinen Sonderweg mehr."""
        for app_id in ("finlai", "norisk", "automate", "teachme"):
            # Root-Datei existiert — sie darf trotzdem ignoriert werden
            (fake_db_dir / f"{app_id}_main.db").touch()

            set_db_app_id(app_id)
            resolved = _get_db_dir_for_name(f"{app_id}_main")
            assert resolved == fake_db_dir / app_id

    def test_customer_ohne_root_datei_bekommt_eigenen_pfad(self, fake_db_dir: Path):
        """Neue Kunden-App ohne Root-Datei → App-spezifisches Verzeichnis."""
        set_db_app_id("teachme_buchhaltung_free")
        resolved = _get_db_dir_for_name("teachme_cheatsheet")
        assert resolved == fake_db_dir / "teachme_buchhaltung_free"

    def test_customer_ignoriert_root_datei(self, fake_db_dir: Path):
        """Kunden-App ignoriert Root-Dateien — strikte Isolation."""
        (fake_db_dir / "teachme_cheatsheet.db").touch()
        (fake_db_dir / "teachings.db").touch()

        set_db_app_id("teachme_buchhaltung_free")
        dir_cheatsheet = _get_db_dir_for_name("teachme_cheatsheet")
        dir_teachings = _get_db_dir_for_name("teachings")

        assert dir_cheatsheet == fake_db_dir / "teachme_buchhaltung_free"
        assert dir_teachings == fake_db_dir / "teachme_buchhaltung_free"

    def test_finlai_und_norisk_isoliert(self, fake_db_dir: Path):
        """FINLAI und NoRisk haben eigene DB-Verzeichnisse."""
        set_db_app_id("finlai")
        pfad_finlai = _get_db_dir_for_name("accounts")

        set_db_app_id("norisk")
        pfad_norisk = _get_db_dir_for_name("accounts")

        assert pfad_finlai == fake_db_dir / "finlai"
        assert pfad_norisk == fake_db_dir / "norisk"
        assert pfad_finlai != pfad_norisk

    def test_zwei_apps_gleicher_db_name_strikt_getrennt(self, fake_db_dir: Path):
        """Identischer db_name in zwei Apps → verschiedene Dateien."""
        set_db_app_id("finlai")
        file_finlai = _get_db_dir_for_name("secure_store") / "secure_store.db"

        set_db_app_id("norisk")
        file_norisk = _get_db_dir_for_name("secure_store") / "secure_store.db"

        assert file_finlai != file_norisk
        assert file_finlai.parent == fake_db_dir / "finlai"
        assert file_norisk.parent == fake_db_dir / "norisk"

    def test_clear_context_kehrt_zu_root_zurueck(self, fake_db_dir: Path):
        """Nach clear_db_app_id → DB_DIR-Root."""
        set_db_app_id("teachme")
        clear_db_app_id()
        resolved = _get_db_dir_for_name("teachings")
        assert resolved == fake_db_dir


# ---------------------------------------------------------------------------
# Konkrete Dateinamen-Tests
# ---------------------------------------------------------------------------


class TestDbDateinamen:
    """Stellt sicher dass die konkreten FINLAI-DB-Namen korrekt isoliert werden."""

    def test_teachme_cheatsheet_db_isoliert(self, fake_db_dir: Path):
        """teachme_cheatsheet.db: TeachMe vs teachMe Accounting vollständig getrennt."""
        set_db_app_id("teachme")
        dir_teachme = _get_db_dir_for_name("teachme_cheatsheet")

        set_db_app_id("teachme_buchhaltung_free")
        dir_buchhalter = _get_db_dir_for_name("teachme_cheatsheet")

        assert dir_teachme != dir_buchhalter
        assert (dir_teachme / "teachme_cheatsheet.db") != (
            dir_buchhalter / "teachme_cheatsheet.db"
        )

    def test_teachings_db_isoliert(self, fake_db_dir: Path):
        """teachings.db: Lernkarten/Templates zwischen Apps isoliert."""
        set_db_app_id("teachme")
        dir_teachme = _get_db_dir_for_name("teachings")

        set_db_app_id("teachme_buchhaltung_free")
        dir_buchhalter = _get_db_dir_for_name("teachings")

        assert dir_teachme != dir_buchhalter

    def test_norisk_dbs_nicht_beeinflusst(self, fake_db_dir: Path):
        """NoRisk-spezifische DBs bleiben in norisk/-Verzeichnis."""
        set_db_app_id("norisk")
        for db_name in ["cert_monitor", "csaf_advisor", "system_scanner"]:
            resolved = _get_db_dir_for_name(db_name)
            assert resolved == fake_db_dir / "norisk", (
                f"DB '{db_name}' sollte in norisk/ liegen, liegt aber in {resolved}"
            )

    def test_finlai_dbs_nicht_beeinflusst(self, fake_db_dir: Path):
        """FINLAI-spezifische DBs bleiben in finlai/-Verzeichnis."""
        set_db_app_id("finlai")
        for db_name in ["accounts", "buchpruefung_checks", "buchpruefung_regeln"]:
            resolved = _get_db_dir_for_name(db_name)
            assert resolved == fake_db_dir / "finlai", (
                f"DB '{db_name}' sollte in finlai/ liegen, liegt aber in {resolved}"
            )
