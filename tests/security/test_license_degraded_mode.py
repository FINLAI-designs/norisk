"""Regression: Deep-Content-Scan laeuft UNBEDINGT — kein Lizenz-Gate mehr.

Diese Datei sicherte frueher den „License Degraded Mode" ab: ohne das Feature
``file_content_validation`` lief ``core.security.import_validator`` nur mit
Magika + Groessen-Check und meldete den INFO-Threat ``LICENSE_DEGRADED_MODE``.

Mit / ist dieses Gate ENTFERNT — der Deep-Content-Scan ist eine
**unbedingte Security-Control** und darf NICHT an einem kommerziellen Lizenz-Flag
haengen. Die Tests kehren die Zusicherung um und verhindern eine Re-Einfuehrung
des Gates — der binding-unabhaengige Hauptschutz ist
``test_no_license_gate_symbols_in_source`` (AST-Scan), die behavioralen Tests
darunter belegen das Laufzeit-Verhalten.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import core.security.import_validator as iv_mod
from core.security import ImportType, validate_import


def _codes(report):
    return [t.code for t in report.threats]


class TestDeepScanUnconditional:
    @pytest.fixture(autouse=True)
    def _no_license(self, monkeypatch):
        """Simuliert „keine Lizenz": FINLAI_DEV entfernt + has_feature=False.

        Defense-in-depth, KEIN alleiniger Guard: ``import_validator`` referenziert
        ``has_feature`` seit nicht mehr (``raising=False``, das Attribut
        existiert dort nicht), darum ist dieser Patch aktuell ein No-op. Er faengt
        nur eine Re-Einfuehrung ueber die exakte Bindung
        ``from core.license_validator import has_feature`` ab — und auf einer
        Maschine mit gueltiger Owner-Lizenz liefert das echte ``has_feature``
        ohnehin True. Der binding-UNABHAENGIGE Schutz steht in
        ``test_no_license_gate_symbols_in_source``.
        """
        monkeypatch.delenv("FINLAI_DEV", raising=False)
        monkeypatch.setattr(
            "core.security.import_validator.has_feature",
            lambda _name: False,
            raising=False,
        )

    def test_deep_scan_runs_without_license(self, make_xlsx):
        # DDE-/CMD-Formel, die nur der Format-Sub-Validator (Deep-Scan) faengt —
        # Magika allein sieht sie nicht. Muss auch ohne Lizenz feuern.
        path = make_xlsx({"B4": "=cmd|'/c calc'!A1"})
        r = validate_import(path, ImportType.XLSX)
        assert "XLSX_FORMULA_INJECTION" in _codes(r)

    def test_no_degraded_mode_threat(self, make_xlsx):
        # Der entfernte INFO-Threat darf nie wieder auftauchen.
        path = make_xlsx({"B4": "=cmd|'/c calc'!A1"})
        r = validate_import(path, ImportType.XLSX)
        assert "LICENSE_DEGRADED_MODE" not in _codes(r)

    def test_type_spoofing_still_caught(self, make_fake_binary):
        # Layer 1 (Magika) bleibt unveraendert — Spoofing wird gefangen.
        path = make_fake_binary(name="tarnung.xlsx")
        r = validate_import(path, ImportType.XLSX)
        codes = _codes(r)
        assert "TYPE_SPOOFING_DANGEROUS" in codes
        assert r.safe_to_parse is False


def test_no_license_gate_symbols_in_source():
    """Binding-unabhaengiger Re-Einfuehrungs-Guard fuer das Lizenz-Gate.

    Statt nur eine konkrete Import-Bindung zu mocken (die ein Wiedereinbau ueber
    ``import core.license_validator as lv; lv.has_feature`` umginge), parst
    dieser Test den AST von ``import_validator`` und stellt sicher, dass im
    LIVE-Code KEINE Lizenz-Gate-Symbole referenziert werden. Docstrings und
    Kommentare (die has_feature aus Traceability-Gruenden nennen) liegen NICHT im
    AST als Name/Attribut und loesen daher keinen Fehlalarm aus. Jede
    Re-Einfuehrung des Deep-Scan-Gates muss has_feature /
    FEATURE_FILE_CONTENT_VALIDATION referenzieren oder importieren -> faellt hier
    auf, unabhaengig von der Import-/Aufruf-Form.
    """
    forbidden = {"has_feature", "FEATURE_FILE_CONTENT_VALIDATION"}
    src = Path(iv_mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)

    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in forbidden:
                    offenders.append(f"import {alias.name} (Zeile {node.lineno})")
        elif isinstance(node, ast.Name) and node.id in forbidden:
            offenders.append(f"Name {node.id} (Zeile {node.lineno})")
        elif isinstance(node, ast.Attribute) and node.attr in forbidden:
            offenders.append(f"Attribut .{node.attr} (Zeile {node.lineno})")

    assert not offenders, (
        "Lizenz-Gate-Symbole im LIVE-Code von import_validator gefunden — der "
        "Deep-Content-Scan darf an KEIN Lizenz-Flag gekoppelt sein "
        "(T-388 / ADR-033):\n" + "\n".join(offenders)
    )
