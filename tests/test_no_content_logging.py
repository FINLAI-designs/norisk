"""No-Content-Logging-Regressionsnetz F-F).

Verankert die Datenschutz-Kernposition des Netzwerk-Monitors („capture-frei =
sauber"): die ETW-/DNS-/Flow-Pipeline loggt ausschließlich **Metadaten**
(Zähler, Dauern, Typnamen, abgeleitete/sanitisierte Werte) — **niemals**
Netzwerk-Inhalte (Paket-Payload, DNS-Query-Namen, Image-Pfade, Zertifikate) im
ausgelieferten Log.

Zwei Mechanismen:

1. **AST-Scan** (alle Log-Level): kein roher Content-Identifier
   (``query_name``/``payload``/``image_path``/…) darf direkt an einen Logger-Aufruf
   übergeben werden. Abgeleitete/sanitisierte Werte (``len(x)``,
   ``type(x).__name__``, ``sanitize_text(x)``) sind erlaubt.
2. **Laufzeit-Log-Capture** (INFO und höher = das ausgelieferte Log-Level):
   feindliche Kanarienvogel-Inhalte durch die echten Normalizer/den ETW-Dispatch
   gespeist tauchen in keinem INFO+-Logrecord auf.

**Bewusste Ausnahme (DOKUMENTIERT, Entscheidung für Patrick):** Der ETW-Roh-Event-
Dump in:meth:`EtwNetworkSubscriber._dispatch` loggt zur Diagnose des (schwer
testbaren) elevierten Collectors die rohen Event-Properties — **gegated** (erste
:data:`_DUMP_LIMIT` Events) und **längen-geklemmt** — auf **DEBUG**. Das Test
``test_etw_rohdump_ist_debug_only`` fixiert, dass dieser Pfad nie auf INFO+ steigt;
DEBUG ist entwickler-only (Auslieferung loggt ab INFO). Offene Frage fürs Review:
soll auch DEBUG inhaltsfrei sein? Dann den Dump auf reine Feldnamen umstellen.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Module, deren Logging inhaltsfrei sein muss (Netzwerk-/ETW-/DNS-/Flow-Pipeline).
_SCAN_DIRS = (
    _REPO_ROOT / "tools" / "network_monitor" / "data",
    _REPO_ROOT / "tools" / "network_monitor" / "application",
)
_SCAN_FILES = (_REPO_ROOT / "apps" / "collector_main.py",)

_LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical", "log"}

#: Roh-Inhalts-/PII-Identifier, die nie direkt geloggt werden dürfen. Bewusst
#: NICHT enthalten: Flow-Metadaten (remote_port, pid, counts) — die sind die
#: legitime Funktion des Monitors. Es geht um *Inhalte* (Payload/Namen/Pfade).
_CONTENT_DENYLIST = {
    "query_name", "queryname", "qname", "query", "domain", "hostname", "fqdn",
    "image_path", "imagename", "imagefilename", "image_raw",
    "payload", "raw_payload", "content", "body", "packet", "banner",
    "cert", "certificate", "peercert", "cmdline", "command_line",
    # DNS-Aggregat-Inhaltsfeld (Review F-F P2). Bewusst NICHT aufgenommen:
    # generische Namen wie ``detail``/``sample`` — die kollidieren mit legitimen
    # Nicht-Inhalts-Logs (z.B. collector_task_manager warnt mit dem untrusted
    # Install-PFAD, den der Admin zum Fixen braucht). Inhalt, der via dict-
    # Schlüssel (``raw.get("query_name")``) gezogen wird, fängt ohnehin die
    # Schlüssel-Rekursion in _collect_identifiers — unabhängig vom Variablennamen.
    "sample_query",
}

#: Aufrufe, deren Ergebnis KEINEN rohen Inhalt mehr trägt (abgeleitet/sanitisiert):
#: ``len(x)`` (Länge), ``type(x)``/``…__name__`` (Klasse), ``sanitize_text(x)``.
#: Nur DIESE werden vom Scan ausgenommen — alles andere (``str``/``repr``/
#: ``.format``/``.get``) wird durchsucht (Review F-F P2: blanket-Call-Exemption
#: ließ ``str(payload)``/``raw.get("query_name")`` durch).
_SAFE_TRANSFORMS = {"len", "type", "sanitize_text"}


def _python_files() -> list[Path]:
    files: list[Path] = list(_SCAN_FILES)
    for d in _SCAN_DIRS:
        files.extend(p for p in d.rglob("*.py") if "__pycache__" not in p.parts)
    return sorted(files)


def _receiver_is_logger(node: ast.expr) -> bool:
    """Heuristik: ist ``node`` ein Logger-Objekt (``_log``/``logger``/``get_logger``)?"""
    if isinstance(node, ast.Name):
        return "log" in node.id.lower()
    if isinstance(node, ast.Attribute):
        return "log" in node.attr.lower()
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id == "get_logger"
        if isinstance(func, ast.Attribute):
            return func.attr == "get_logger"
    return False


def _iter_logger_calls(tree: ast.AST):
    """Yield alle ``<logger>.<method>``-Call-Nodes."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _LOG_METHODS
            and _receiver_is_logger(func.value)
        ):
            yield node


def _call_func_name(call: ast.Call) -> str | None:
    """Name der aufgerufenen Funktion (``len`` / ``str`` / ``get`` / ``format`` …)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _collect_identifiers(node: ast.expr, out: set[str]) -> None:
    """Sammelt rekursiv alle Roh-Content-Kandidaten unter ``node``.

    Prunt **nur** echte Safe-Transforms (:data:`_SAFE_TRANSFORMS`) — deren
    Argumente werden NICHT durchsucht. Bei jedem anderen Aufruf (``str``/``repr``/
    ``.format``/``.get``) wird in die Argumente abgestiegen, sodass
    ``str(payload)`` → ``payload`` und ``raw.get("query_name")`` → ``"query_name"``
    erfasst werden. ``Attribute`` liefert seinen Endnamen (``event.query_name`` →
    ``query_name``); ``Subscript``/``Constant``-Strings liefern den Schlüssel.
    """
    if isinstance(node, ast.Call):
        if _call_func_name(node) in _SAFE_TRANSFORMS:
            return  # len(payload)/type(x)/sanitize_text(x) → Ergebnis ist sicher
        for arg in node.args:
            _collect_identifiers(arg, out)
        for kw in node.keywords:
            _collect_identifiers(kw.value, out)
        return
    if isinstance(node, ast.Name):
        out.add(node.id)
        return
    if isinstance(node, ast.Attribute):
        out.add(node.attr)  # Endname genügt (kein Abstieg in den Empfänger)
        return
    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            out.add(node.slice.value)
        _collect_identifiers(node.value, out)
        return
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            out.add(node.value)  # dict-Schlüssel wie "QueryName"
        return
    if isinstance(node, ast.JoinedStr):
        for fv in node.values:
            if isinstance(fv, ast.FormattedValue):
                _collect_identifiers(fv.value, out)
        return
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.expr):
            _collect_identifiers(child, out)


def _logged_identifiers(call: ast.Call) -> set[str]:
    """Alle Roh-Content-Kandidaten der Logger-Argumente.

    Ein **direktes** Constant-String-Argument ist die Format-Zeichenkette
    (``"query %s"``) und wird übersprungen — nur ihre interpolierten/nachfolgenden
    Werte zählen. Geschachtelte Constants (dict-Schlüssel in ``.get``/
    ``[...]``) werden von:func:`_collect_identifiers` weiterhin erfasst.
    """
    out: set[str] = set()
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        if isinstance(arg, ast.Constant):
            continue  # Format-/Literal-String, kein Inhalt
        _collect_identifiers(arg, out)
    return out


def _content_violations(path: Path) -> list[str]:
    """Findet Logger-Aufrufe, die einen Roh-Content-Identifier übergeben."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    try:
        label = str(path.relative_to(_REPO_ROOT))
    except ValueError:
        label = path.name  # Datei außerhalb des Repos (Selbsttest mit tmp_path)
    violations: list[str] = []
    for call in _iter_logger_calls(tree):
        for ident in _logged_identifiers(call):
            if ident.lower() in _CONTENT_DENYLIST:
                violations.append(f"{label}:{call.lineno} loggt '{ident}'")
    return violations


# ── 1) AST-Scan ──────────────────────────────────────────────────────────────


class TestNoContentIdentifierLogging:
    def test_scan_findet_dateien(self) -> None:
        # Schutz gegen einen leeren Scan (Pfad-Tippfehler täuschte sonst Grün vor).
        files = _python_files()
        assert len(files) >= 5
        names = {p.name for p in files}
        assert "etw_network_subscriber.py" in names
        assert "dns_event_normalizer.py" in names

    def test_kein_roher_content_identifier_im_logging(self) -> None:
        violations: list[str] = []
        for path in _python_files():
            violations.extend(_content_violations(path))
        assert not violations, "Content-Logging gefunden:\n" + "\n".join(violations)

    def test_denylist_wuerde_verstoss_fangen(self, tmp_path: Path) -> None:
        # Selbsttest: ein synthetischer Verstoß MUSS gefunden werden (sonst ist
        # der Scanner blind — Reward-Hacking-Schutz).
        bad = tmp_path / "bad.py"
        bad.write_text(
            "import logging\n"
            "_log = logging.getLogger('x')\n"
            "def f(query_name):\n"
            "    _log.info('q=%s', query_name)\n",
            encoding="utf-8",
        )
        assert _content_violations(bad)

    def test_abgeleitete_werte_sind_erlaubt(self, tmp_path: Path) -> None:
        # len/sanitize_text/type.__name__ dürfen NICHT als Verstoß zählen.
        ok = tmp_path / "ok.py"
        ok.write_text(
            "import logging\n"
            "_log = logging.getLogger('x')\n"
            "def f(payload, name):\n"
            "    _log.info('bytes=%d typ=%s', len(payload), type(payload).__name__)\n"
            "    _log.debug('q=%s', sanitize_text(name))\n",
            encoding="utf-8",
        )
        assert _content_violations(ok) == []

    def test_call_wrapped_content_wird_gefangen(self, tmp_path: Path) -> None:
        # Review F-F P2: str/repr/.format/.get/Subscript dürfen den Scan
        # NICHT umgehen — sonst gibt das Netz falsche Sicherheit.
        bad = tmp_path / "bad.py"
        bad.write_text(
            "import logging\n"
            "_log = logging.getLogger('x')\n"
            "def f(payload, raw):\n"
            "    _log.info('a=%s', str(payload))\n"
            "    _log.info('b=%s', raw.get('query_name'))\n"
            "    _log.info('c=%s', raw['QueryName'])\n"
            "    _log.info('d={}'.format(raw.get('image_path')))\n",
            encoding="utf-8",
        )
        violations = _content_violations(bad)
        # Alle vier Muster müssen gefangen werden.
        joined = " ".join(violations)
        assert "payload" in joined
        assert "query_name" in joined
        assert "QueryName" in joined
        assert "image_path" in joined


# ── 2) Laufzeit-Log-Capture (INFO+) ─────────────────────────────────────────

_CANARY_DOMAIN = "ZZCANARYDNS9988776655443322.example.invalid"
_CANARY_PATH = r"C:\Users\geheim\ZZCANARYEXE7766554433221100.exe"
# IBAN-artige Sequenz (lange Ziffernfolge) als zweiter Kanarienvogel.
_CANARY_IBAN = "DE89370400440532013000"


def _assert_clean(caplog: pytest.LogCaptureFixture) -> None:
    text = caplog.text
    assert _CANARY_DOMAIN not in text
    assert _CANARY_PATH not in text
    assert _CANARY_IBAN not in text
    assert "99887766" not in text  # lange Ziffernfolge
    assert "77665544" not in text


class TestNoContentInShippedLogs:
    """Laufzeit-Backstop für die inhalts-berührenden Pipeline-Eingänge (INFO+).

    Deckt die drei Stellen ab, an denen feindlicher Inhalt real durch die Pipeline
    fließt: den ETW-Dispatch (loggt heute Roh-Props nur auf DEBUG) sowie die
    DNS-/Image-Normalizer. Letztere loggen **heute nichts** — die Tests sind dort
    bewusst **Vorwärts-Regressionswächter**: fügt jemand künftig ein
    content-haltiges INFO-Log hinzu, schlagen sie an. Die *statische*
    Voll-Abdeckung ALLER gescannten Module liefert der AST-Scan
    (:class:`TestNoContentIdentifierLogging`); dieser Laufzeitteil ergänzt ihn um
    den dynamischen Beweis an den heißen Eingängen.
    """

    def test_etw_dispatch_kein_content_in_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from tools.network_monitor.data.etw_network_subscriber import (
            EtwNetworkSubscriber,
        )

        sub = EtwNetworkSubscriber(lambda eid, raw: None)
        raw = {
            "EventHeader": {"ProcessId": 1234},
            "QueryName": _CANARY_DOMAIN,
            "ImageName": _CANARY_PATH,
            "extra": _CANARY_IBAN,
        }
        with caplog.at_level(logging.INFO, logger="finlai"):
            for _ in range(3):
                sub._dispatch((3006, raw))
        _assert_clean(caplog)

    def test_etw_dispatch_kein_content_in_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """/F-F: Der DEBUG-Roh-Dump ist jetzt SCHEMA-only — auch auf DEBUG
        landet kein Inhalt (kein Carve-out mehr). Geloggt werden nur Feldname +
        Typ/Länge, nie der Wert."""
        from tools.network_monitor.data.etw_network_subscriber import (
            EtwNetworkSubscriber,
        )

        sub = EtwNetworkSubscriber(lambda eid, raw: None)
        raw = {
            "EventHeader": {"ProcessId": 1234},
            "QueryName": _CANARY_DOMAIN,
            "ImageName": _CANARY_PATH,
            "extra": _CANARY_IBAN,
        }
        with caplog.at_level(logging.DEBUG, logger="finlai"):
            for _ in range(3):
                sub._dispatch((3006, raw))
        _assert_clean(caplog)
        # Positiv-Kontrolle: das Schema (Feldnamen + Typ/Länge) wird sehr wohl geloggt.
        assert "QueryName" in caplog.text
        assert "<str:" in caplog.text

    def test_dns_normalizer_kein_content_in_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from tools.network_monitor.data.dns_event_normalizer import normalize_dns_event

        with caplog.at_level(logging.INFO, logger="finlai"):
            out = normalize_dns_event(
                {"EventHeader": {"ProcessId": 1}, "QueryName": _CANARY_DOMAIN}
            )
        # Der sanitisierte Name fließt in die DB (Funktion), aber NICHT ins Log.
        assert out.get("query_name") == _CANARY_DOMAIN
        _assert_clean(caplog)

    def test_process_path_tracker_kein_content_in_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from tools.network_monitor.data.process_path_tracker import (
            KERNEL_PROCESS_START_EVENT_ID,
            ProcessPathTracker,
        )

        tracker = ProcessPathTracker()
        with caplog.at_level(logging.INFO, logger="finlai"):
            tracker.add_event(
                KERNEL_PROCESS_START_EVENT_ID,
                {"ProcessID": 4242, "ImageName": _CANARY_PATH},
            )
        _assert_clean(caplog)


# ── 3) DEBUG-Carve-out fixieren ──────────────────────────────────────────────


def _format_constant(call: ast.Call) -> str:
    """Die Format-Zeichenkette eines Logger-Calls (erstes Constant-String-Arg)."""
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return ""


class TestEtwDumpDebugOnly:
    def test_roh_repr_dumps_sind_debug_only(self) -> None:
        """Jeder Logger-Call mit ``%r`` (Repr-Dump) darf nur auf DEBUG loggen.

        Der ETW-Diagnose-Dump nutzt ``%r`` für das Event-**Schema** (Feldname +
        Typ/Länge, seit/F-F INHALTSFREI — kein Roh-Wert mehr). Diese Prüfung
        ist an das ``%r``-Marker gekoppelt (NICHT an einen Variablennamen — Review
        F-F P3), sodass JEDER künftige ``%r``-Dump in der Pipeline DEBUG-only bleibt;
        die Inhaltsfreiheit des konkreten Dumps deckt
:meth:`TestNoContentInShippedLogs.test_etw_dispatch_kein_content_in_debug` ab.
        """
        repr_levels: list[str] = []
        for path in _python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for call in _iter_logger_calls(tree):
                if "%r" in _format_constant(call) and isinstance(
                    call.func, ast.Attribute
                ):
                    repr_levels.append(call.func.attr)
        assert repr_levels, "Erwarteter ETW-Roh-%r-Dump nicht gefunden (Drift?)"
        assert all(level == "debug" for level in repr_levels), (
            f"Roh-%r-Dump nicht DEBUG-only: {repr_levels}"
        )
