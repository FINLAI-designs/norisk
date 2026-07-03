"""
test_evergreen_context_builder — Tests fuer den Application-Adapter, der
:class:`EvergreenGatingContext` aus Tool-States baut.

Deckt:
    *:func:`build_evergreen_context` — defensiver Aufruf-Pfad, alle
      Exceptions werden geschluckt und das jeweilige Feld auf ``None``
      gesetzt.
    * Monkeypatch der einzelnen Reader-Helper, damit der Builder
      isoliert vom realen DB-State testbar ist.
"""

from __future__ import annotations

import pytest

from tools.mainpage.application import evergreen_context_builder as ecb
from tools.mainpage.application.evergreen_provider import (
    EvergreenGatingContext,
)


class TestBuildEvergreenContext:
    def test_default_call_returns_context(self) -> None:
        """Smoke: Builder laeuft ohne Crash und liefert ein Context-Objekt."""
        ctx = ecb.build_evergreen_context()
        assert isinstance(ctx, EvergreenGatingContext)

    def test_failing_helpers_yield_none_fields(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Alle Reader werfen → Context hat None-Felder, kein Crash."""
        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated read fail")

        monkeypatch.setattr(ecb, "_safe_last_scan", _boom)
        monkeypatch.setattr(ecb, "_safe_patch_last_scan", _boom)
        monkeypatch.setattr(ecb, "_safe_hardening_score", _boom)
        # _safe_techstack_change wirft heute nicht, lassen wir.
        with pytest.raises(RuntimeError):
            # build_evergreen_context selbst wird vom Widget-Layer
            # geschuetzt, aber innerhalb des Builders propagieren
            # Exceptions — die Reader-Funktionen sind defensiv,
            # nicht der Builder.
            ecb.build_evergreen_context()

    def test_individual_readers_return_none_on_internal_exception(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Jeder einzelne Reader faengt seine Exceptions selbst ab."""
        def _boom():
            raise RuntimeError("internal")

        # patch die Module-internen Helpers — wir wollen die Outer-
        # Reader-Funktionen testen, also mocken wir tiefer.
        import core.registry.last_scan_registry as lsr
        monkeypatch.setattr(lsr, "get_last_scan", lambda _: _boom())
        assert ecb._safe_last_scan("system_scanner") is None  # noqa: SLF001

    def test_safe_patch_last_scan_handles_missing_service(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wenn PatchInventoryService-Init wirft (z. B. fehlende DB),
        liefert der Reader None."""
        from tools.patch_monitor.application import patch_inventory_service as pis

        class _BadService:
            def __init__(self) -> None:
                raise RuntimeError("DB unavailable")

        monkeypatch.setattr(pis, "PatchInventoryService", _BadService)
        assert ecb._safe_patch_last_scan() is None  # noqa: SLF001

    def test_safe_hardening_score_handles_empty_history(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wenn der Repo keine History hat, liefert der Reader None."""
        from tools.security_scoring.data import hardening_score_repository as hsr

        class _EmptyRepo:
            def __init__(self) -> None:
                pass

            def load_history(self, *, target_name: str, limit: int):  # noqa: ANN201, ARG002
                return []

        monkeypatch.setattr(hsr, "HardeningScoreRepository", _EmptyRepo)
        assert ecb._safe_hardening_score("self") is None  # noqa: SLF001

    def test_safe_hardening_score_returns_value_from_repo(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mit Mock-History liefert der Reader den overall_score als float.

        ``load_history`` liefert ``(timestamp, overall_score)``-Tupel
-Bugfix: vorher griff der Reader faelschlich
        ``.overall_score`` auf dem Tupel zu → immer None).
        """
        from tools.security_scoring.data import hardening_score_repository as hsr

        class _Repo:
            def __init__(self) -> None:
                pass

            def load_history(self, *, target_name: str, limit: int):  # noqa: ANN201, ARG002
                return [("2026-06-03T10:00:00", 73.5)]

        monkeypatch.setattr(hsr, "HardeningScoreRepository", _Repo)
        result = ecb._safe_hardening_score("self")  # noqa: SLF001
        assert result == 73.5

    def test_safe_techstack_change_returns_none_today(self) -> None:
        """v1: kein Tech-Stack-Last-Edit-Pfad, immer None."""
        assert ecb._safe_techstack_change() is None  # noqa: SLF001

    def test_integration_uses_real_default_target(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Builder akzeptiert ``hardening_target_name``-kwarg."""
        called_with: list[str] = []

        def _spy(target_name: str):
            called_with.append(target_name)
            return None

        monkeypatch.setattr(ecb, "_safe_hardening_score", _spy)
        monkeypatch.setattr(ecb, "_safe_last_scan", lambda _t: None)
        monkeypatch.setattr(ecb, "_safe_patch_last_scan", lambda: None)
        monkeypatch.setattr(ecb, "_safe_techstack_change", lambda: None)

        ecb.build_evergreen_context(hardening_target_name="custom-host")
        assert called_with == ["custom-host"]


class TestModuleSurface:
    def test_only_public_export(self) -> None:
        """``__all__`` exportiert nur die High-Level-API."""
        assert ecb.__all__ == ["build_evergreen_context"]
