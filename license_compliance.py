"""GPLv2-Sperrlisten-Build-Check F-G, fail-closed).

Verhindert, dass GPLv2-/Npcap-kontaminierende Komponenten in den **kommerziellen**
NoRisk-Build geraten. Die Stratoshark/Wireshark-Integrationsroadmap
(NoRisk_WIRESHARK_STRATOSHARK_INTEGRATION.md) verbietet ausdrücklich das Linken/
Bündeln von ``pyshark``/``libwireshark``/``tshark``/``wireshark``/``stratoshark``,
``Npcap`` sowie der Qt-``Charts``-Module (GPLv3/kommerziell, NICHT LGPL wie der
restliche Qt-Kern).

Geprüft wird auf vier Ebenen — jede ist **fail-closed** (ein Treffer bricht den
Build ab):

1. **Installierte Distributions** (``importlib.metadata``) — z. B. ``pyshark``.
2. **Importe im eigenen Code** (AST über ``tools/``/``core/``/``apps/``) — fängt
   ``from PySide6.QtCharts import …`` unabhängig davon, dass QtCharts mit PySide6
   stets *verfügbar* ist (verboten ist die *Nutzung*/das Bündeln, nicht die
   Verfügbarkeit).
3. **Spec-Text** (``build_norisk.spec``) — keine verbotenen ``hiddenimports``/Datas.
4. **Gebündelte Binärdateien** (``dist/norisk/_internal``) — keine ``npcap``/
   ``wireshark``/``Qt6Charts``-DLLs (Post-Build / Test).

Aufruf aus der Spec (Build bricht ab, bevor PyInstaller etwas baut)::

    import sys, os
    sys.path.insert(0, ROOT)
    from license_compliance import assert_build_compliant
    assert_build_compliant(repo_root=ROOT)

CLI::

    python license_compliance.py # Code + Installiert + Spec
    python license_compliance.py --bundle dist/norisk # zusätzlich Bundle

Autor: Patrick Riederich
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import sys
import tokenize
from pathlib import Path

# ── Sperrlisten ─────────────────────────────────────────────────────────────

#: Verbotene Python-Distributionen (pip-Namen, case-insensitiv).
FORBIDDEN_DISTRIBUTIONS: frozenset[str] = frozenset(
    {"pyshark", "pypcap", "pcapy", "pcapy-ng", "scapy", "libpcap", "pylibpcap"}
)

#: Verbotene Import-Wurzeln (Modul == X ODER beginnt mit ``X.``). Erfasst sowohl
#: GPL-Sniffer-Bindings als auch die GPL/kommerziellen Qt-Charts-Module.
FORBIDDEN_IMPORT_ROOTS: frozenset[str] = frozenset(
    {
        "pyshark",
        "pcap",
        "pcapy",
        "scapy",
        "sinsp",
        "falco",
        "PySide6.QtCharts",
        "PyQt6.QtCharts",
        "PySide6.QtDataVisualization",
        "PyQt6.QtDataVisualization",
    }
)

#: Verbotene Teil-Strings im Spec-Quelltext (case-insensitiv). Geprüft wird nur
#: der **Code ohne Kommentare** (:func:`_code_without_comments`), damit
#: erklärende Kommentare (die diese Namen zwangsläufig nennen) nicht selbst
#: auslösen. QtCharts ist hier bewusst NICHT gelistet — die Spec *schließt* es
#: legitim via ``excludes`` aus; seine Inklusion fängt der Code-Import-Scan
#: (``FORBIDDEN_IMPORT_ROOTS``) und der Bundle-Scan (``Qt6Charts.dll``).
FORBIDDEN_SPEC_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "pyshark",
        "libwireshark",
        "tshark",
        "wireshark",
        "stratoshark",
        "npcap",
        "winpcap",
        "libsinsp",
        "falco",
        "scapy",
        "pcapy",
    }
)

#: Verbotene Teil-Strings in gebündelten Binär-Dateinamen (case-insensitiv).
#: Enthält sowohl die Qt-DLL-Namen (``qt6charts``) als auch die PySide6-Binding-
#: Module (``qtcharts`` → ``QtCharts.pyd``/``.abi3.so``).
FORBIDDEN_BINARY_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "npcap",
        "wpcap",
        "winpcap",
        "wireshark",
        "tshark",
        "stratoshark",
        "libwireshark",
        "libsinsp",
        "qtcharts",
        "qt6charts",
        "qtdatavisualization",
        "qt6datavisualization",
    }
)

#: Quell-Verzeichnisse, die auf verbotene Importe geprüft werden.
_SOURCE_DIRS: tuple[str, ...] = ("tools", "core", "apps")


class LicenseComplianceError(RuntimeError):
    """Fail-closed: eine verbotene (GPL/Npcap) Komponente wurde gefunden."""


# ── Einzel-Scanner ───────────────────────────────────────────────────────────


def _normalize_dist(name: str) -> str:
    """PEP-503-Normalisierung eines Distributionsnamens (``-``/``_``/``.`` → ``-``)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


#: Vorab normalisierte Sperrliste — vermeidet Umgehung via ``_``/``.``-Schreibweise.
_FORBIDDEN_DISTRIBUTIONS_NORM: frozenset[str] = frozenset(
    _normalize_dist(n) for n in FORBIDDEN_DISTRIBUTIONS
)


def scan_installed_distributions() -> list[str]:
    """Findet installierte, verbotene Python-Distributionen (PEP-503-normalisiert)."""
    from importlib import metadata  # noqa: PLC0415 — lazy, nur beim Check

    violations: list[str] = []
    for dist in metadata.distributions():
        raw = (dist.metadata["Name"] or "").strip()
        if _normalize_dist(raw) in _FORBIDDEN_DISTRIBUTIONS_NORM:
            violations.append(f"Installiertes Paket verboten: {raw}")
    return violations


def _import_roots(tree: ast.AST):
    """Yield die Modulnamen aller import-Statements eines AST.

    Für ``from X import a, b`` werden NICHT nur ``X`` geliefert, sondern auch die
    voll-qualifizierten ``X.a``/``X.b`` — so wird ``from PySide6 import QtCharts``
    als ``PySide6.QtCharts`` erkannt (Review F-G P2: die idiomatischste QtCharts-
    Importform entging sonst dem Code-Scan).
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                yield node.module
                for alias in node.names:
                    if alias.name != "*":
                        yield f"{node.module}.{alias.name}"


def _is_forbidden_import(module: str) -> bool:
    return any(
        module == root or module.startswith(root + ".")
        for root in FORBIDDEN_IMPORT_ROOTS
    )


def scan_source_imports(repo_root: Path) -> list[str]:
    """AST-Scan des eigenen Codes auf verbotene Importe (QtCharts/pyshark/…)."""
    violations: list[str] = []
    for rel in _SOURCE_DIRS:
        base = repo_root / rel
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for module in _import_roots(tree):
                if _is_forbidden_import(module):
                    violations.append(
                        f"Verbotener Import '{module}' in {path.relative_to(repo_root)}"
                    )
    return violations


def scan_spec_text(spec_path: Path) -> list[str]:
    """Findet verbotene Teil-Strings im Spec-Quelltext."""
    if not spec_path.is_file():
        return []
    return scan_text(spec_path.read_text(encoding="utf-8"), source=spec_path.name)


def _code_without_comments(text: str) -> str:
    """Gibt den Python-Code OHNE Kommentare zurück (String-Literale bleiben).

    So lösen erklärende ``#``-Kommentare, die die verbotenen Namen zwangsläufig
    erwähnen, den Substring-Scan NICHT aus — eine echte Inklusion (z. B.
    ``hiddenimports=["pyshark"]``) bleibt als String-Literal aber sichtbar.
    Bei Tokenize-Fehlern (Fragment) fällt es auf den Rohtext zurück (konservativ).
    """
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        return " ".join(
            tok.string for tok in tokens if tok.type != tokenize.COMMENT
        )
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text


def scan_text(text: str, *, source: str) -> list[str]:
    """Findet verbotene Spec-Substrings im Code (ohne Kommentare) — Tests/CLI."""
    lowered = _code_without_comments(text).lower()
    return [
        f"Verbotener Spec-Bezug '{needle}' in {source}"
        for needle in sorted(FORBIDDEN_SPEC_SUBSTRINGS)
        if needle in lowered
    ]


def scan_bundle(dist_dir: Path) -> list[str]:
    """Findet verbotene Binär-Dateinamen in einem gebauten Bundle (Post-Build)."""
    if not dist_dir.is_dir():
        return []
    violations: list[str] = []
    for path in dist_dir.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        for needle in FORBIDDEN_BINARY_SUBSTRINGS:
            if needle in name:
                violations.append(f"Verbotene Bundle-Datei: {path.name} ({needle})")
                break
    return violations


# ── Aggregat ─────────────────────────────────────────────────────────────────


def scan_catalog_provenance(repo_root: Path) -> list[str]:
    """5. Ebene (system_tuner R3): der Tweak-Katalog muss AGPL-frei sein.

    Prueft jeden ``provenance.license``-Eintrag in
    ``resources/system_tuner/catalog*.yaml``: enthaelt er ``gpl`` (deckt
    GPL/AGPL/LGPL ab), ist es ein Verstoss (Clean-Room-Gate, fail-closed).
    Spiegelt den Ladezeit-Check im ``catalog_loader`` auf der Build-Ebene.

    Args:
        repo_root: Repo-Wurzel.

    Returns:
        Liste der Verstoss-Beschreibungen (leer = sauber).
    """
    import yaml  # noqa: PLC0415 — nur fuer diese Ebene benoetigt

    violations: list[str] = []
    catalog_dir = repo_root / "resources" / "system_tuner"
    if not catalog_dir.is_dir():
        return violations
    for path in sorted(catalog_dir.glob("catalog*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            violations.append(f"system_tuner-Katalog nicht lesbar: {path.name} ({exc})")
            continue
        for tweak in (data or {}).get("tweaks", []) or []:
            prov = (tweak or {}).get("provenance") or {}
            license_str = str(prov.get("license") or "").lower()
            if "gpl" in license_str:
                violations.append(
                    f"system_tuner-Katalog {path.name}: Tweak "
                    f"{(tweak or {}).get('id', '?')} hat (A)GPL-Provenance-Lizenz "
                    f"'{prov.get('license')}' — Katalog muss AGPL-frei sein (R3)"
                )
    return violations


def check_build_compliance(
    repo_root: Path,
    *,
    bundle_dir: Path | None = None,
    check_installed: bool = True,
) -> list[str]:
    """Führt alle anwendbaren Scans aus und gibt die Verstöße zurück.

    Args:
        repo_root: Repo-Wurzel (enthält ``tools/``/``core/``/``apps/`` + Spec).
        bundle_dir: Optionales gebautes Bundle (z. B. ``dist/norisk``); ``None``
            überspringt den Binär-Scan (existiert beim Spec-Lauf noch nicht).
        check_installed: Installierte Distributionen mitprüfen (Default ``True``).

    Returns:
        Liste der Verstoß-Beschreibungen (leer = sauber).
    """
    repo_root = Path(repo_root)
    violations: list[str] = []
    if check_installed:
        violations += scan_installed_distributions()
    violations += scan_source_imports(repo_root)
    violations += scan_spec_text(repo_root / "build_specs" / "build_norisk.spec")
    violations += scan_catalog_provenance(repo_root)
    if bundle_dir is not None:
        violations += scan_bundle(Path(bundle_dir))
    return violations


def assert_build_compliant(
    repo_root: Path | str,
    *,
    bundle_dir: Path | None = None,
    check_installed: bool = True,
) -> None:
    """Fail-closed: wirft:class:`LicenseComplianceError`, wenn ein Verstoß vorliegt.

    Args:
        repo_root: Repo-Wurzel.
        bundle_dir: Optionales gebautes Bundle.
        check_installed: Installierte Distributionen mitprüfen.

    Raises:
        LicenseComplianceError: Bei mindestens einem Verstoß (Build abbrechen).
    """
    violations = check_build_compliance(
        Path(repo_root), bundle_dir=bundle_dir, check_installed=check_installed
    )
    if violations:
        raise LicenseComplianceError(
            "GPLv2-/Npcap-Sperrliste verletzt — Build abgebrochen (T-340 F-G):\n  - "
            + "\n  - ".join(violations)
        )


def _main(argv: list[str] | None = None) -> int:
    """CLI-Einstieg: Exit 0 = sauber, Exit 1 = Verstoß (fail-closed)."""
    parser = argparse.ArgumentParser(description="NoRisk GPLv2-Sperrlisten-Build-Check")
    parser.add_argument(
        "--bundle", type=Path, default=None, help="Pfad zum gebauten Bundle (dist/norisk)"
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parent
    )
    args = parser.parse_args(argv)
    violations = check_build_compliance(args.repo_root, bundle_dir=args.bundle)
    if violations:
        print("LIZENZ-CHECK FEHLGESCHLAGEN (T-340 F-G):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    print("Lizenz-Check OK — keine verbotenen GPL/Npcap-Komponenten.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
