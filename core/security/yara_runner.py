"""
yara_runner — Lazy-singleton YARA-Engine fuer den Document Scanner.

Iteration 3: Erweitert die ``validate_import``-
Pipeline um eine typ-agnostische YARA-Stage. YARA matched Patterns
quer ueber den Datei-Inhalt — also unabhaengig davon, ob's ein PDF,
DOCX oder eine Skript-Datei ist.

Architektur:
    - YARA-Regeln liegen in ``resources/yara_rules/*.yar``.
    - Compile-Cache wird ueber mtime der Regeldateien invalidiert
      (Hot-Update bei der naechsten App-Session).
    - Wenn ``yara-python`` fehlt: scan_path liefert ``[]`` und der
      Validator ergaenzt einen ``YARA_UNAVAILABLE``-INFO-Threat.

Schichtzugehoerigkeit: core/security/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from core.logger import get_logger

_log = get_logger(__name__)

#: Verzeichnis mit YARA-Regeln. Eine Datei = ein Regel-Set.
RULES_DIR: Path = Path(__file__).resolve().parents[2] / "resources" / "yara_rules"

#: Max-Groesse fuer YARA-Scan in Bytes. Sehr grosse Dateien (z. B.
#: 10 MB JSON) bremsen die ``validate_import``-Pipeline auf >2 s ohne
#: realistischen YARA-Mehrwert — Pattern-Matches treten in Dokumenten
#: i. d. R. innerhalb der ersten paar MB auf. Wir ueberspringen dann
#: den Scan ueberlassen die Bewertung den typspezifischen Sub-
#: Validatoren.
MAX_SCAN_BYTES: int = 8 * 1024 * 1024  # 8 MB


@dataclass(frozen=True)
class YaraMatch:
    """Eine einzelne YARA-Treffer-Zeile.

    Attributes:
        rule: Regelname (z. B. ``"NoRisk_PS_Empire_Stager"``).
        tags: Tag-Liste aus ``meta:`` (severity:high, family:...,...).
        meta: Komplettes meta-Dict (severity, description, family,...).
        strings: Anzahl gematchter Strings (Stichprobe — nicht die Werte
                  selbst, die koennten sensibel sein).
    """

    rule: str
    tags: list[str]
    meta: dict[str, str]
    strings_count: int


_rules_cache = None
_rules_mtime: float = 0.0
_rules_lock = Lock()


def _yara_available() -> bool:
    """True wenn das yara-python-Modul importierbar ist."""
    try:
        import yara  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def _max_mtime(rules_dir: Path) -> float:
    """Maximaler mtime aller ``*.yar``-Dateien — fuer Cache-Invalidation."""
    if not rules_dir.exists():
        return 0.0
    mtimes = [f.stat().st_mtime for f in rules_dir.glob("*.yar")]
    return max(mtimes, default=0.0)


def _compile_rules(rules_dir: Path):  # type: ignore[no-untyped-def]
    """Kompiliert alle ``*.yar``-Dateien im Verzeichnis in ein Rules-Objekt.

    Bei einem einzelnen kaputten Regel-File wird das gesamte Compile
    geblockt — wir loggen + geben ``None`` zurueck. Der Aufrufer
    behandelt ``None`` wie "yara nicht verfuegbar".
    """
    import yara  # noqa: PLC0415

    filepaths: dict[str, str] = {}
    for f in rules_dir.glob("*.yar"):
        filepaths[f.stem] = str(f)
    if not filepaths:
        _log.warning("YARA: keine Regeldateien in %s", rules_dir)
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except yara.SyntaxError as exc:
        _log.error("YARA: Regel-Compile fehlgeschlagen: %s", exc)
        return None


def _get_rules():  # type: ignore[no-untyped-def]
    """Liefert das kompilierte Rules-Objekt (gecached + mtime-invalidiert)."""
    global _rules_cache, _rules_mtime

    if not _yara_available():
        return None

    current = _max_mtime(RULES_DIR)
    with _rules_lock:
        if _rules_cache is None or current > _rules_mtime:
            _rules_cache = _compile_rules(RULES_DIR)
            _rules_mtime = current
    return _rules_cache


def is_available() -> bool:
    """True wenn YARA-Engine + Regeln nutzbar sind."""
    return _yara_available() and _get_rules() is not None


def scan_path(path: Path, timeout_seconds: int = 10) -> list[YaraMatch]:
    """Scannt eine Datei gegen alle geladenen YARA-Regeln.

    Args:
        path: Zu scannende Datei.
        timeout_seconds: Hardes Timeout je Match (yara-internal).

    Returns:
        Liste der Treffer. Leer wenn YARA nicht verfuegbar / keine
        Regeln / kein Treffer.
    """
    rules = _get_rules()
    if rules is None:
        return []
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            _log.debug(
                "YARA-Scan uebersprungen — Datei zu gross (%d > %d)",
                path.stat().st_size,
                MAX_SCAN_BYTES,
            )
            return []
        matches = rules.match(str(path), timeout=timeout_seconds)
    except Exception as exc:  # noqa: BLE001 -- YARA-Lib kann Lib-spezifische Errors werfen
        _log.warning("YARA-Scan-Fehler fuer %s: %s", path.name, exc)
        return []

    result: list[YaraMatch] = []
    for m in matches:
        meta = {k: str(v) for k, v in (getattr(m, "meta", {}) or {}).items()}
        tags = list(getattr(m, "tags", []) or [])
        strings_count = len(getattr(m, "strings", []) or [])
        result.append(
            YaraMatch(rule=m.rule, tags=tags, meta=meta, strings_count=strings_count)
        )
    return result
