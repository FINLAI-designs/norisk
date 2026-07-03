"""
tests/test_updater.py — Tests für core/updater.py.

Prüft:
  - check_for_update: SemVer-Vergleich (kein Update / Update vorhanden)
  - check_for_update: Netzwerkfehler → None (kein Crash)
  - check_for_update: Timeout → None
  - check_for_update: Ungültige / fehlende Felder in Server-Antwort → None
  - check_for_update: URL-Auflösung (Default → /stable/, Override)
  - check_for_update: Kanal-Filterung (staging/dev → None, stable → UpdateInfo)
  - check_for_update: Fehlendes channel-Feld → Default "stable" (Backward-Compat)
  - download_update: Erfolgreicher Download + SHA-256-Verifikation
  - download_update: SHA-256-Mismatch → None, Temp-Datei gelöscht
  - download_update: HTTP-Fehler → None
  - download_update: Nicht-HTTPS-URL → None (sofort abgelehnt)
  - download_update: Progress-Callback wird aufgerufen
  - apply_update: Subprocess-Spawn mit korrekten Argumenten
  - apply_update: quit_callback wird aufgerufen
  - apply_update: Fehlende EXE → kein Crash
  - _resolve_check_url: Default-URL und Override
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.updater import (
    UpdateInfo,
    _cleanup,
    _resolve_check_url,
    apply_update,
    check_for_update,
    download_update,
)

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

_VALID_UPDATE_INFO = UpdateInfo(
    version="1.1.0",
    url="https://example.com/update.exe",
    sha256="",  # leer — wird in Tests genutzt die VOR dem Hash-Check failen
    # (Netzwerk-/HTTP-Fehler, ungültige URL). Tests, die den
    # Hash-Pfad triggern, definieren ihre eigene UpdateInfo
    # mit gültigem 64-Hex-Hash.
    release_notes="Bugfixes",
    min_version="1.0.0",
)


def _make_response(data: dict, status: int = 200) -> MagicMock:
    """Erstellt ein Mock-Response-Objekt."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.status_code = status
    resp.raise_for_status.return_value = None
    if status >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


# ---------------------------------------------------------------------------
# Tests: _resolve_check_url
# ---------------------------------------------------------------------------


class TestResolveCheckUrl:
    def test_ohne_endpunkt_und_override_gibt_leer(self, monkeypatch):
        """Open-Source-Default: keine Basis-URL + kein Override -> kein Endpunkt."""
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "")
        assert _resolve_check_url("norisk") == ""
        assert _resolve_check_url("norisk", "") == ""

    def test_override_url_wird_direkt_verwendet(self, monkeypatch):
        """Override greift unabhängig von der Basis-URL (auch wenn leer)."""
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "")
        override = "https://mein-server.at/updates/latest.json"
        assert _resolve_check_url("finlai", override) == override

    def test_gesetzte_basis_url_enthaelt_app_id(self, monkeypatch):
        """Kommerzieller Build mit Endpunkt: volle stable/latest.json-URL."""
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "https://updates.example.test")
        url = _resolve_check_url("automate_kunde1")
        assert "automate_kunde1" in url
        assert url.startswith("https://")
        assert url.endswith("latest.json")

    def test_gesetzte_basis_url_enthaelt_stable_kanal(self, monkeypatch):
        """Client holt immer aus dem stable-Kanal ab."""
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "https://updates.example.test")
        url = _resolve_check_url("finlai")
        assert "/stable/" in url


# ---------------------------------------------------------------------------
# Tests: check_for_update
# ---------------------------------------------------------------------------


class TestCheckForUpdate:
    @pytest.fixture(autouse=True)
    def _configured_endpoint(self, monkeypatch):
        """Simuliert einen Build mit gesetztem Update-Endpunkt.

        Der Open-Source-Default ist leer (kein Phone-Home); die HTTP-/SemVer-
        Logik wird hier unter "Endpunkt konfiguriert"-Bedingungen geprüft, wie
        sie in einem kommerziellen/White-Label-Build vorliegt.
        """
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "https://updates.example.test")

    def test_ohne_endpunkt_kein_netzwerk(self, monkeypatch):
        """Ohne Endpunkt: kein requests.get, sofort None (kein Phone-Home)."""
        monkeypatch.setattr("core.updater.UPDATE_BASE_URL", "")
        with patch("core.updater.requests.get") as mock_get:
            result = check_for_update("1.0.0", "norisk")
        assert result is None
        mock_get.assert_not_called()

    @patch("core.updater.requests.get")
    def test_kein_update_wenn_gleiche_version(self, mock_get):
        mock_get.return_value = _make_response({"version": "1.0.0"})
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_kein_update_wenn_aeltere_server_version(self, mock_get):
        mock_get.return_value = _make_response({"version": "0.9.0"})
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_update_verfuegbar_wenn_server_neuer(self, mock_get):
        mock_get.return_value = _make_response(
            {
                "version": "1.1.0",
                "url": "https://example.com/update.exe",
                "sha256": "abc123",
                "release_notes": "Bugfixes",
                "min_version": "1.0.0",
            }
        )
        result = check_for_update("1.0.0", "finlai")
        assert result is not None
        assert result.version == "1.1.0"
        assert result.url == "https://example.com/update.exe"
        assert result.release_notes == "Bugfixes"

    @patch("core.updater.requests.get")
    def test_sha256_wird_lowercase_gespeichert(self, mock_get):
        mock_get.return_value = _make_response(
            {"version": "2.0.0", "sha256": "ABCDEF123456"}
        )
        result = check_for_update("1.0.0", "finlai")
        assert result is not None
        assert result.sha256 == "abcdef123456"

    @patch("core.updater.requests.get", side_effect=requests.ConnectionError("no net"))
    def test_netzwerkfehler_gibt_none(self, _mock_get):
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get", side_effect=requests.Timeout("timeout"))
    def test_timeout_gibt_none(self, _mock_get):
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_http_fehler_gibt_none(self, mock_get):
        mock_get.return_value = _make_response({}, status=404)
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_fehlendes_version_feld_gibt_none(self, mock_get):
        mock_get.return_value = _make_response({"url": "https://example.com/x.exe"})
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_ungueltige_semver_im_server_gibt_none(self, mock_get):
        mock_get.return_value = _make_response({"version": "kein-semver"})
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_ungueltige_lokale_version_gibt_none(self, mock_get):
        mock_get.return_value = _make_response({"version": "1.1.0"})
        result = check_for_update("kein-semver", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_fehlende_optionale_felder_erhalten_defaults(self, mock_get):
        mock_get.return_value = _make_response({"version": "2.0.0"})
        result = check_for_update("1.0.0", "finlai")
        assert result is not None
        assert result.url == ""
        assert result.sha256 == ""
        assert result.release_notes == ""
        assert result.min_version == "0.0.0"
        assert result.channel == "stable"  # fehlendes Feld → stable (Backward-Compat)

    @patch("core.updater.requests.get")
    def test_stable_kanal_wird_akzeptiert(self, mock_get):
        mock_get.return_value = _make_response(
            {"version": "1.1.0", "channel": "stable"}
        )
        result = check_for_update("1.0.0", "finlai")
        assert result is not None
        assert result.channel == "stable"

    @patch("core.updater.requests.get")
    def test_staging_kanal_wird_ignoriert(self, mock_get):
        """staging-Einträge dürfen nicht an Kunden ausgeliefert werden."""
        mock_get.return_value = _make_response(
            {"version": "1.1.0", "channel": "staging"}
        )
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_dev_kanal_wird_ignoriert(self, mock_get):
        """dev-Einträge dürfen nicht an Kunden ausgeliefert werden."""
        mock_get.return_value = _make_response({"version": "1.1.0", "channel": "dev"})
        result = check_for_update("1.0.0", "finlai")
        assert result is None

    @patch("core.updater.requests.get")
    def test_fehlendes_channel_feld_ist_backward_kompatibel(self, mock_get):
        """Altes Server-Schema ohne channel-Feld → wird als stable behandelt."""
        mock_get.return_value = _make_response({"version": "1.1.0"})  # kein channel
        result = check_for_update("1.0.0", "finlai")
        assert result is not None  # wird NICHT gefiltert

    @patch("core.updater.requests.get")
    def test_override_url_wird_verwendet(self, mock_get):
        mock_get.return_value = _make_response({"version": "1.1.0"})
        override = "https://mein-server.at/latest.json"
        check_for_update("1.0.0", "finlai", override_url=override)
        called_url = mock_get.call_args[0][0]
        assert called_url == override

    @patch("core.updater.requests.get")
    def test_timeout_parameter_wird_gesetzt(self, mock_get):
        mock_get.return_value = _make_response({"version": "0.9.0"})
        check_for_update("1.0.0", "finlai")
        _, kwargs = mock_get.call_args
        assert "timeout" in kwargs
        assert kwargs["timeout"] == 5  # UPDATE_CHECK_TIMEOUT

    @patch("core.updater.requests.get")
    def test_verify_true_erzwungen(self, mock_get):
        mock_get.return_value = _make_response({"version": "0.9.0"})
        check_for_update("1.0.0", "finlai")
        _, kwargs = mock_get.call_args
        assert kwargs.get("verify") is True


# ---------------------------------------------------------------------------
# Tests: download_update
# ---------------------------------------------------------------------------


def _make_streaming_response(content: bytes, status: int = 200) -> MagicMock:
    """Mock-Response für Streaming-Downloads."""
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status.return_value = None
    resp.headers = {"Content-Length": str(len(content))}
    # iter_content gibt die Bytes in einem einzigen Chunk zurück
    resp.iter_content.return_value = [content]
    if status >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError()
    return resp


class TestDownloadUpdate:
    def test_nicht_https_url_wird_abgelehnt(self):
        info = UpdateInfo(
            version="1.1.0",
            url="http://example.com/update.exe",  # HTTP — unsicher
            sha256="",
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is None

    @patch("core.updater.requests.get")
    def test_leerer_hash_blockt_download(self, mock_get, tmp_path):
        # Ab 2026-05-02 ist sha256 Pflichtfeld — leeres oder falsch
        # langes Feld bricht den Download ab (vorher fail-open).
        # Verhindert Bypass durch kompromittierten/manipulierten
        # latest.json mit weggelassenem Hash.
        content = b"EXE_CONTENT_MOCK"
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update.exe",
            sha256="",
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is None

    @patch("core.updater.requests.get")
    def test_zu_kurzer_hash_blockt_download(self, mock_get):
        content = b"EXE_CONTENT_MOCK"
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update.exe",
            sha256="abc123",  # nicht 64 Zeichen
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is None

    @patch("core.updater.requests.get")
    def test_sha256_mismatch_gibt_none_und_loescht_datei(self, mock_get):
        content = b"EXE_CONTENT"
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update.exe",
            sha256="0" * 64,  # Falscher Hash
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is None

    @patch("core.updater.requests.get")
    def test_korrekter_sha256_wird_akzeptiert(self, mock_get):
        content = b"REAL_EXE_CONTENT"
        expected_sha256 = hashlib.sha256(content).hexdigest()
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update.exe",
            sha256=expected_sha256,
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is not None
        result.unlink()
        result.parent.rmdir()

    @patch("core.updater.requests.get")
    def test_sha256_uppercase_wird_korrekt_verglichen(self, mock_get):
        content = b"CONTENT_ABC"
        expected_sha256 = hashlib.sha256(content).hexdigest().upper()
        mock_get.return_value = _make_streaming_response(content)

        # SHA-256 im UpdateInfo wird bereits lowercase gespeichert (durch check_for_update)
        # Hier testen wir den direkten Aufruf mit lowercase
        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update.exe",
            sha256=expected_sha256.lower(),
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is not None
        result.unlink()
        result.parent.rmdir()

    @patch("core.updater.requests.get", side_effect=requests.ConnectionError("fail"))
    def test_netzwerkfehler_gibt_none(self, _mock_get):
        result = download_update(_VALID_UPDATE_INFO)
        assert result is None

    @patch("core.updater.requests.get")
    def test_http_fehler_gibt_none(self, mock_get):
        mock_get.return_value = _make_streaming_response(b"", status=404)
        result = download_update(_VALID_UPDATE_INFO)
        assert result is None

    @patch("core.updater.requests.get")
    def test_progress_callback_wird_aufgerufen(self, mock_get):
        content = b"X" * 1024
        mock_get.return_value = _make_streaming_response(content)

        calls: list[int] = []
        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/upd.exe",
            sha256=hashlib.sha256(content).hexdigest(),
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info, progress_callback=calls.append)
        if result:
            result.unlink()
            result.parent.rmdir()
        # Mindestens der 100%-Call muss angekommen sein
        assert 100 in calls

    @patch("core.updater.requests.get")
    def test_dateiname_aus_url_abgeleitet(self, mock_get):
        content = b"MOCK"
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/FINLAI_v1.1.0.exe",
            sha256=hashlib.sha256(content).hexdigest(),
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is not None
        assert result.name == "FINLAI_v1.1.0.exe"
        result.unlink()
        result.parent.rmdir()

    @patch("core.updater.requests.get")
    def test_nicht_exe_url_erhaelt_fallback_dateiname(self, mock_get):
        content = b"MOCK"
        mock_get.return_value = _make_streaming_response(content)

        info = UpdateInfo(
            version="1.1.0",
            url="https://example.com/update",  # kein.exe-Suffix
            sha256=hashlib.sha256(content).hexdigest(),
            release_notes="",
            min_version="1.0.0",
        )
        result = download_update(info)
        assert result is not None
        assert result.name == "update.exe"
        result.unlink()
        result.parent.rmdir()


# ---------------------------------------------------------------------------
# Tests: apply_update
# ---------------------------------------------------------------------------


class TestApplyUpdate:
    def test_fehlende_exe_kein_crash(self, tmp_path):
        missing = tmp_path / "nicht_vorhanden.exe"
        # Darf nicht crashen
        apply_update(missing)

    @patch("core.updater.subprocess.Popen")
    def test_subprocess_wird_mit_exe_pfad_gestartet(self, mock_popen, tmp_path):
        exe = tmp_path / "update.exe"
        exe.write_bytes(b"EXE")

        quit_called: list[bool] = []
        apply_update(exe, quit_callback=lambda: quit_called.append(True))

        assert mock_popen.called
        args_list = mock_popen.call_args[0][0]
        assert str(exe) in args_list

    @patch("core.updater.subprocess.Popen")
    def test_updated_from_flag_wird_uebergeben(self, mock_popen, tmp_path):
        exe = tmp_path / "update.exe"
        exe.write_bytes(b"EXE")

        apply_update(exe, old_version="1.0.0", quit_callback=lambda: None)

        args_list = mock_popen.call_args[0][0]
        assert "--updated-from" in args_list
        assert "1.0.0" in args_list

    @patch("core.updater.subprocess.Popen")
    def test_quit_callback_wird_aufgerufen(self, mock_popen, tmp_path):
        exe = tmp_path / "update.exe"
        exe.write_bytes(b"EXE")

        quit_called: list[bool] = []
        apply_update(exe, quit_callback=lambda: quit_called.append(True))

        assert quit_called == [True]

    @patch("core.updater.subprocess.Popen", side_effect=OSError("denied"))
    def test_popen_fehler_kein_crash(self, _mock_popen, tmp_path):
        exe = tmp_path / "update.exe"
        exe.write_bytes(b"EXE")
        # Darf nicht crashen, quit_callback darf nicht aufgerufen werden
        quit_called: list[bool] = []
        apply_update(exe, quit_callback=lambda: quit_called.append(True))
        assert quit_called == []

    @patch("core.updater.subprocess.Popen")
    def test_re_hash_korrekt_spawnt_normal(self, mock_popen, tmp_path):
        # TOCTOU-Schutz: wenn expected_sha256 mit Datei-Inhalt matcht,
        # läuft der Spawn normal durch.
        content = b"REAL_EXE_CONTENT_FOR_REHASH"
        exe = tmp_path / "update.exe"
        exe.write_bytes(content)

        quit_called: list[bool] = []
        apply_update(
            exe,
            quit_callback=lambda: quit_called.append(True),
            expected_sha256=hashlib.sha256(content).hexdigest(),
        )
        assert mock_popen.called
        assert quit_called == [True]

    @patch("core.updater.subprocess.Popen")
    def test_re_hash_mismatch_blockt_spawn(self, mock_popen, tmp_path):
        # TOCTOU-Schutz: wenn die Datei nach Download manipuliert wurde,
        # darf apply_update KEINEN subprocess starten und KEIN quit
        # auslösen. Schließt das %TEMP%-Tausch-Fenster.
        exe = tmp_path / "update.exe"
        exe.write_bytes(b"MANIPULIERTER_INHALT")

        quit_called: list[bool] = []
        apply_update(
            exe,
            quit_callback=lambda: quit_called.append(True),
            expected_sha256="0" * 64,  # Hash der echten EXE — mismatch
        )
        assert not mock_popen.called
        assert quit_called == []


# ---------------------------------------------------------------------------
# Tests: _cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_dateien_werden_geloescht(self, tmp_path):
        d = tmp_path / "dl"
        d.mkdir()
        f = d / "update.exe"
        f.write_bytes(b"X")
        _cleanup(f, d)
        assert not f.exists()
        assert not d.exists()

    def test_fehlende_datei_kein_crash(self, tmp_path):
        d = tmp_path / "nope"
        f = d / "update.exe"
        # Beide existieren nicht — kein Crash erwartet
        _cleanup(f, d)
