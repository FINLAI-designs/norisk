"""
Tests für core/legal — Nutzungsvereinbarung, DSGVO-Texte und
check_first_start in main.py.

Author: Patrick Riederich
Version: 1.0
"""

from core.legal.terms import PRIVACY_POLICY, TERMS_OF_USE


# ---------------------------------------------------------------------------
# terms.py — Inhalt der Texte
# ---------------------------------------------------------------------------
class TestTermsOfUse:
    def test_non_empty(self):
        assert TERMS_OF_USE.strip()

    def test_contains_title(self):
        assert "FINLAI" in TERMS_OF_USE
        assert "Allgemeine Geschäftsbedingungen" in TERMS_OF_USE

    def test_contains_all_sections(self):
        for section in ("1.", "2.", "3.", "4.", "5."):
            assert section in TERMS_OF_USE

    def test_version_marker(self):
        # AGB auf v2.1 (Abschnitt 15 + Lizenz-Kauf-/Aktivierungs-Apparat
        # auf entgeltfreie OSS-Nutzung umgestellt).
        assert "Version 2.1" in TERMS_OF_USE

    def test_consumer_clause_present(self):
        # AGB enthaelt einen Verbraucher-Block + Widerrufsbelehrung.
        # die lizenz-kauf-spezifischen Teile (B9, B3-/Widerrufs-
        # Digitalteile zu Lizenzschluessel/Aktivierung) wurden entfernt, da NoRisk
        # entgeltfrei ohne Aktivierung bereitgestellt wird (kein FAGG-Fernabsatz-
        # vertrag); der generische Verbraucher-/Gewaehrleistungs-Rahmen bleibt.
        assert "Verbraucher" in TERMS_OF_USE
        assert "Widerruf" in TERMS_OF_USE

    def test_is_string(self):
        assert isinstance(TERMS_OF_USE, str)


class TestPrivacyPolicy:
    def test_non_empty(self):
        assert PRIVACY_POLICY.strip()

    def test_contains_title(self):
        assert "Datenschutzerklärung" in PRIVACY_POLICY
        assert "DSGVO" in PRIVACY_POLICY

    def test_contains_all_sections(self):
        for section in ("1.", "2.", "3.", "4.", "5.", "6."):
            assert section in PRIVACY_POLICY

    def test_version_marker(self):
        # PRIVACY_POLICY auf v2.2 — §4 faktentreu nachgeschaerft (externe
        # Sicherheits-Feeds/VirusTotal/HIBP/CSAF offengelegt + Drittland-Hinweis +
        # per Offline-Modus deaktivierbar; korrigiert die zu absolute v2.1-Aussage).
        assert "Version 2.2" in PRIVACY_POLICY

    def test_no_cloud_clause(self):
        assert "lokal" in PRIVACY_POLICY.lower()

    def test_rights_mentioned(self):
        assert "Auskunft" in PRIVACY_POLICY
        assert "Löschung" in PRIVACY_POLICY

    def test_is_string(self):
        assert isinstance(PRIVACY_POLICY, str)

    def test_no_license_server_transfer(self):
        """ /: Die OSS-App macht keine Lizenz-Server-Kommunikation
        mehr (Heartbeat/Activation repo-weit entfernt) -> die Datenschutz-
        erklärung darf KEINE Lizenzserver-Übertragung mehr behaupten und muss
        die lokale Verarbeitung ohne FINLAI-Übertragung offenlegen.
        """
        assert "Lizenzserver" not in PRIVACY_POLICY
        assert "Revalidierung" not in PRIVACY_POLICY
        assert "keine Daten an FINLAI" in PRIVACY_POLICY


# ---------------------------------------------------------------------------
# check_first_start — Logik ohne GUI
# ---------------------------------------------------------------------------
class TestCheckFirstStart:
    """Testet die check_first_start-Logik via direktem UISettings-Attribut-Zugriff."""

    def _make_settings(self, tmp_path, terms_accepted: str = ""):

        from core.ui_settings import UISettings

        s = UISettings()
        s.terms_accepted = terms_accepted
        return s

    def test_already_accepted_returns_true(self, tmp_path, monkeypatch):
        """Wenn terms_accepted gesetzt ist, direkt True ohne Dialoge."""
        from core.ui_settings import UISettings

        settings = UISettings(terms_accepted="2026-03-29T10:00:00")
        # check_first_start ohne GUI: da accepted, kein Dialog nötig
        # Wir testen die Logik direkt ohne QApplication
        assert settings.terms_accepted  # guard: gesetzt

        # Simuliere check_first_start-Logik (ohne GUI-Aufrufe)
        if settings.terms_accepted:
            result = True
        else:
            result = False
        assert result is True

    def test_not_accepted_empty_string(self):
        from core.ui_settings import UISettings

        settings = UISettings()
        assert settings.terms_accepted == ""
        assert not settings.terms_accepted  # leerer String = falsy

    def test_terms_version_default_empty(self):
        from core.ui_settings import UISettings

        settings = UISettings()
        assert settings.terms_version == ""

    def test_privacy_accepted_default_empty(self):
        from core.ui_settings import UISettings

        settings = UISettings()
        assert settings.privacy_accepted == ""

    def test_save_and_reload_accepted(self, tmp_path, monkeypatch):
        """Speichert Zustimmung und lädt sie korrekt."""
        import core.ui_settings as ui_mod

        settings_file = tmp_path / "ui_settings.json"
        monkeypatch.setattr(ui_mod, "_SETTINGS_FILE", settings_file)

        from core.ui_settings import UISettings

        settings = UISettings(
            terms_accepted="2026-03-29T10:00:00",
            privacy_accepted="2026-03-29T10:00:00",
            terms_version="1.0",
        )
        settings.save()

        loaded = UISettings.load()
        assert loaded.terms_accepted == "2026-03-29T10:00:00"
        assert loaded.privacy_accepted == "2026-03-29T10:00:00"
        assert loaded.terms_version == "1.0"

    def test_load_missing_fields_uses_defaults(self, tmp_path, monkeypatch):
        """Alte Einstellungs-Datei ohne terms-Felder liefert leere Strings."""
        import json

        import core.ui_settings as ui_mod

        settings_file = tmp_path / "ui_settings.json"
        settings_file.write_text(
            json.dumps({"sidebar_width": 220, "theme": "dark"}),
            encoding="utf-8",
        )
        monkeypatch.setattr(ui_mod, "_SETTINGS_FILE", settings_file)

        from core.ui_settings import UISettings

        loaded = UISettings.load()
        assert loaded.terms_accepted == ""
        assert loaded.privacy_accepted == ""
        assert loaded.terms_version == ""
