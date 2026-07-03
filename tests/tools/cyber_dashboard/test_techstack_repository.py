"""
test_techstack_repository — Regression-Tests für den leeren Default-Stack.

Absichert:
  - ``lade`` liefert eine leere Liste wenn die Stack-Datei fehlt
    (früher: 8 hardcodierte AT-Kanzlei-Einträge → Beta-Tester hielten
    sie für Entwicklerdaten).
  - ``AT_STARTER_STACK`` existiert weiterhin mit 8 kuratierten Einträgen
    und ist über den Techstack-Tab opt-in ladbar.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.cyber_dashboard.data import techstack_repository as repo_module
from tools.cyber_dashboard.data.techstack_repository import (
    AT_STARTER_STACK,
    DEFAULT_STACK,
    TechStackRepository,
)


@pytest.fixture()
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TechStackRepository:
    """TechStackRepository mit isoliertem Stack-Pfad unter tmp_path."""
    monkeypatch.setattr(repo_module, "STACK_PATH", tmp_path / "techstack.json")
    return TechStackRepository()


class TestDefaultStack:
    """DEFAULT_STACK ist leer — frische Installationen zeigen nichts an."""

    def test_default_stack_ist_leer(self) -> None:
        assert DEFAULT_STACK == []

    def test_lade_ohne_datei_gibt_leere_liste(self, repo: TechStackRepository) -> None:
        assert repo.lade() == []

    def test_lade_kaputte_datei_gibt_leere_liste(
        self, repo: TechStackRepository, tmp_path: Path
    ) -> None:
        (tmp_path / "techstack.json").write_text("not-json-{{", encoding="utf-8")
        assert repo.lade() == []


class TestAtStarterStack:
    """AT_STARTER_STACK ist die Opt-in-Vorschlagsliste für AT-Kanzleien."""

    def test_at_starter_stack_hat_acht_eintraege(self) -> None:
        assert len(AT_STARTER_STACK) == 8

    def test_at_starter_stack_enthaelt_kanzlei_produkte(self) -> None:
        namen = {e.name for e in AT_STARTER_STACK}
        assert {"Windows", "Python", "BMD", "Microsoft Office"}.issubset(namen)

    def test_starter_eintraege_sind_aktiv(self) -> None:
        assert all(e.aktiv for e in AT_STARTER_STACK)


class TestCrud:
    """Grundlegender CRUD-Pfad — bleibt unverändert."""

    def test_hinzufuegen_und_lade(self, repo: TechStackRepository) -> None:
        repo.hinzufuegen(AT_STARTER_STACK[0])
        geladen = repo.lade()
        assert len(geladen) == 1
        assert geladen[0].name == AT_STARTER_STACK[0].name


class TestCpeFeld:
    """: das ``cpe``-Feld überlebt save→load und ist back-compatible."""

    def test_cpe_roundtrip(self, repo: TechStackRepository) -> None:
        from tools.cyber_dashboard.domain.models import TechStackEintrag

        cpe = "cpe:2.3:a:python:python:3.12:*:*:*:*:*:*:*"
        repo.speichere([TechStackEintrag(name="Python", version="3.12", cpe=cpe)])
        geladen = repo.lade()
        assert len(geladen) == 1
        assert geladen[0].cpe == cpe

    def test_alte_json_ohne_cpe_laedt_mit_leerem_default(
        self, repo: TechStackRepository, tmp_path: Path
    ) -> None:
        # Alt-Bestand: JSON ohne ``cpe``-Schlüssel (vor geschrieben).
        (tmp_path / "techstack.json").write_text(
            '[{"name": "Windows", "version": "11", "kategorie": "OS", '
            '"aktiv": true}]',
            encoding="utf-8",
        )
        geladen = repo.lade()
        assert len(geladen) == 1
        assert geladen[0].name == "Windows"
        assert geladen[0].cpe == ""
