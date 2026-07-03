"""
test_system_tuner_result_cleanup — Aufräumen des Ergebnis-Markers.

Der elevierte Kindprozess schreibt den Ergebnis-Marker in die admin-only Ablage
(``%ProgramData%\\NoRisk``); der nicht-elevierte Parent kann ihn dort LESEN, aber
nicht LÖSCHEN (``PermissionError``/WinError 5). Vor dem Fix ließ das die ganze
Apply-Operation crashen, obwohl das Apply erfolgreich war und der Marker gelesen
wurde. Getestet wird:

* ``_best_effort_unlink`` schluckt ``PermissionError`` (kein Crash).
* ``_sweep_stale_results`` löscht verwaiste Marker, behält den aktuellen und lässt
  Ledger/Plan/Snapshots unangetastet.
* ``request_elevated_apply`` liefert das (gelesene + HMAC-verifizierte) Ergebnis
  auch dann, wenn das Aufräumen des Markers mit ``PermissionError`` scheitert.

Author: Patrick Riederich
"""

from __future__ import annotations

import tools.system_tuner.application.elevated_round_trip as ert
from tools.system_tuner.domain.apply_entities import BatchResult, TweakResult
from tools.system_tuner.domain.enums import TweakStatus

_SECRET = b"0123456789abcdef0123456789abcdef"


class _RaisingPath:
    """Fake-Pfad, dessen ``unlink`` immer ``PermissionError`` wirft."""

    def unlink(self, missing_ok: bool = False) -> None:  # noqa: FBT001, FBT002
        raise PermissionError("[WinError 5] Zugriff verweigert")


class TestBestEffortUnlink:
    def test_swallows_permissionerror(self):
        # Darf NICHT werfen — Aufräumen ist unkritisch.
        ert._best_effort_unlink(_RaisingPath(), what="Test")

    def test_deletes_existing_file(self, tmp_path):
        f = tmp_path / "result_x.json"
        f.write_text("{}", encoding="utf-8")
        ert._best_effort_unlink(f, what="Test")
        assert not f.exists()


class TestSweepStaleResults:
    def test_deletes_stale_keeps_current_and_others(self, tmp_path):
        (tmp_path / "result_alt.json").write_text("{}", encoding="utf-8")
        (tmp_path / "result_aktuell.json").write_text("{}", encoding="utf-8")
        (tmp_path / "used_tokens.json").write_text("[]", encoding="utf-8")  # Ledger
        (tmp_path / "plan_x.json").write_text("{}", encoding="utf-8")

        ert._sweep_stale_results(tmp_path, keep_token="aktuell")

        assert not (tmp_path / "result_alt.json").exists()  # verwaist -> weg
        assert (tmp_path / "result_aktuell.json").exists()  # aktueller Marker bleibt
        assert (tmp_path / "used_tokens.json").exists()  # Ledger unberührt
        assert (tmp_path / "plan_x.json").exists()  # Plan unberührt

    def test_swallows_glob_oserror(self):
        # Der Sweep darf den elevierten Prozess NIE killen — auch das Auflisten
        # (glob) ist best-effort (P3-Härtung: sonst kein Reject-Marker, GUI-Timeout).
        class _RaisingDir:
            def glob(self, _pattern):
                raise OSError("Ablage weg")

        ert._sweep_stale_results(_RaisingDir(), keep_token="x")  # darf nicht werfen


class TestRequestReturnsResultDespiteCleanupFailure:
    def test_permissionerror_on_cleanup_does_not_fail_operation(
        self, tmp_path, monkeypatch
    ):
        expected = BatchResult((TweakResult("TW-1", TweakStatus.APPLIED, "ok"),))

        monkeypatch.setattr(ert, "get_active_key_manager", lambda: object())
        monkeypatch.setattr(ert, "_apply_hmac_secret", lambda _km: _SECRET)
        monkeypatch.setattr(ert, "default_signature_path", lambda: tmp_path / "no.sig")
        monkeypatch.setattr(
            ert,
            "bind_plan",
            lambda token, ids, sig, *, secret: type(
                "_B", (), {"to_dict": lambda self: {"token": token}}
            )(),
        )
        monkeypatch.setattr(ert, "write_plan", lambda _payload: tmp_path / "plan.json")
        monkeypatch.setattr(ert, "relaunch_elevated", lambda *a, **k: True)
        monkeypatch.setattr(ert, "secure_dir", lambda: tmp_path)
        monkeypatch.setattr(
            ert, "read_result", lambda token, *, store_dir, secret: expected
        )
        # Der Marker liegt admin-only → Löschen wirft PermissionError.
        monkeypatch.setattr(ert, "_result_path", lambda store, token: _RaisingPath())

        result = ert.request_elevated_apply(["TW-1"])

        assert result is expected  # Ergebnis zurück, kein Crash trotz Cleanup-Fehler


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
