"""network_monitor.application.conversation_filter — deklarativer Filter (Phase 5).

Sicherer, **eval-freier** Filter für die Konversations-Tabelle. Zwei Ebenen:

  -:func:`apply_chips` — Laien-Default: Toggle-Chips (nur verdächtige / nur externe)
    + freie Volltext-Suche (Substring über Prozess/IP/Status).
  -:func:`parse_filter` — Experten-Modus: ein deklarativer Ausdruck über einer
    **Whitelist** von Feldern und Operatoren, UND-verknüpft. Der Parser baut reine
    Prädikat-Funktionen; es wird **niemals** ``eval``/``exec`` aufgerufen. Unbekannte
    Felder/Operatoren/Werte enden in einer:class:`ConversationFilterError`, nicht in
    Code-Ausführung.

Grammatik (Experten-Ausdruck)::

    ausdruck:= klausel ((UND) klausel)* UND ∈ {und, and, &&}
    klausel:= feld OP wert
    feld ∈ {prozess, ip, port, status, verdaechtig, verbindungen,...}
    OP ∈ {=, ==, !=, >, <, >=, <=, ~, in, contains}

Beispiele::

    prozess ~ chrome und ip in 10.0.0.0/8
    verdaechtig = ja
    port >= 1024 und status = established
    verbindungen > 50

Schichtzugehörigkeit: ``application/`` — reine Logik, kein DB-/GUI-Bezug.

Author: Patrick Riederich
Version: 1.0 Phase 5)
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable

from tools.network_monitor.data.blocklist_loader import parse_network_token
from tools.network_monitor.domain.exceptions import ConversationFilterError
from tools.network_monitor.domain.models import Conversation

#: Prädikat über eine Konversation.
Predicate = Callable[[Conversation], bool]

#: Feld-Alias → interner Feld-Typ (Whitelist; alles andere wird abgelehnt).
_FIELD_TYPES: dict[str, str] = {
    "prozess": "process",
    "process": "process",
    "ip": "ip",
    "port": "port",
    "ports": "port",
    "status": "status",
    "verdaechtig": "bool",
    "verdächtig": "bool",
    "suspicious": "bool",
    "verbindungen": "count",
    "anzahl": "count",
    "count": "count",
    "bytes": "bytes",
    "byte": "bytes",
}

#: Menschliche Liste der erlaubten Felder (für Fehlermeldungen).
ALLOWED_FIELDS: tuple[str, ...] = (
    "prozess",
    "ip",
    "port",
    "status",
    "verdaechtig",
    "verbindungen",
    "bytes",
)

#: Symbol-Operatoren, längste zuerst (für korrektes Matching).
_SYMBOL_OPS: tuple[str, ...] = (">=", "<=", "!=", "==", "=", ">", "<", "~")
#: Wort-Operatoren (leerzeichen-begrenzt).
_WORD_OPS: tuple[str, ...] = ("in", "contains")

#: Wahr-/Falsch-Tokens für boolesche Felder.
_TRUE_TOKENS = frozenset({"ja", "true", "wahr", "1", "yes", "y"})
_FALSE_TOKENS = frozenset({"nein", "false", "falsch", "0", "no", "n"})

#: Trennt einen Ausdruck an UND-Verknüpfungen (case-insensitiv).
_AND_SPLIT = re.compile(r"\s+(?:und|and)\s+|\s*&&\s*", re.IGNORECASE)


# ── Laien-Chips + Suche ───────────────────────────────────────────────────────


def is_external_ip(ip: str) -> bool:
    """``True`` wenn ``ip`` eine öffentlich routbare Adresse ist (für „nur extern").

    Nutzt ``is_global`` — das schließt nicht nur private/lokale Adressen aus, sondern
    auch reservierte Bereiche (CGNAT 100.64/10, Benchmark 198.18/15, TEST-NET,
    6to4-Anycast …), die sonst fälschlich als „extern" gälten (Review SEC-1).
    Nicht-parsebare IPs gelten als nicht-extern (konservativ; kein Crash).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


def apply_chips(
    conversations: Iterable[Conversation],
    *,
    only_suspicious: bool = False,
    only_external: bool = False,
    search: str = "",
) -> list[Conversation]:
    """Wendet die Laien-Chips + Volltext-Suche an (alle Bedingungen UND-verknüpft).

    Args:
        conversations: Eingangs-Konversationen.
        only_suspicious: Nur als verdächtig markierte Konversationen.
        only_external: Nur Konversationen mit externer (nicht-privater) Ziel-IP.
        search: Substring (case-insensitiv) über Prozessname, IP und Status.

    Returns:
        Gefilterte Liste (Reihenfolge bleibt erhalten).
    """
    term = search.strip().lower()
    result: list[Conversation] = []
    for conv in conversations:
        if only_suspicious and not conv.suspicious:
            continue
        if only_external and not is_external_ip(conv.remote_ip):
            continue
        if term and not _matches_search(conv, term):
            continue
        result.append(conv)
    return result


def _matches_search(conv: Conversation, term: str) -> bool:
    if term in conv.process_name.lower() or term in conv.remote_ip.lower():
        return True
    return any(term in status.lower() for status in conv.statuses)


# ── Experten-Filter (deklarativ, kein eval) ───────────────────────────────────


def parse_filter(expr: str) -> Predicate:
    """Parst einen Experten-Ausdruck zu einem UND-verknüpften Prädikat.

    Args:
        expr: Der Filter-Ausdruck (leer → Prädikat das immer ``True`` liefert).

    Returns:
        Ein:data:`Predicate`, das eine Konversation gegen ALLE Klauseln prüft.

    Raises:
        ConversationFilterError: Bei unbekanntem Feld, unzulässigem Operator oder
            nicht passendem Wert. Es wird nie Code ausgewertet.
    """
    expr = expr.strip()
    if not expr:
        return lambda _conv: True
    clauses = [c.strip() for c in _AND_SPLIT.split(expr) if c.strip()]
    predicates = [_parse_clause(c) for c in clauses]

    def combined(conv: Conversation) -> bool:
        return all(predicate(conv) for predicate in predicates)

    return combined


def _parse_clause(clause: str) -> Predicate:
    """Zerlegt eine einzelne ``feld OP wert``-Klausel in ein Prädikat."""
    field_raw, op, value = _split_clause(clause)
    field = field_raw.strip().lower()
    field_type = _FIELD_TYPES.get(field)
    if field_type is None:
        raise ConversationFilterError(
            f"Unbekanntes Feld '{field_raw.strip()}'. Erlaubt: "
            + ", ".join(ALLOWED_FIELDS)
            + "."
        )
    value = value.strip()
    if not value:
        raise ConversationFilterError(f"Kein Wert für '{field}' angegeben.")
    builder = _BUILDERS[field_type]
    return builder(op, value)


def _split_clause(clause: str) -> tuple[str, str, str]:
    """Findet den **linkesten** Operator und teilt in (feld, op, wert).

    Es wird der am weitesten links beginnende Operator gewählt (bei gleicher
    Startposition der längere, sodass ``>=`` vor ``>`` gewinnt). So zerlegt ein
    Wert, der selbst ein Operator-Zeichen oder ein freistehendes ``in``/``contains``
    enthält, nicht fälschlich am Wert statt am echten Operator-Review C1/C2).
    """
    candidates: list[tuple[int, int, str]] = []  # (start, end, op)
    # Wort-Operatoren (leerzeichen-begrenzt, case-insensitiv).
    for word_op in _WORD_OPS:
        match = re.search(rf"\s+{word_op}\s+", clause, re.IGNORECASE)
        if match:
            candidates.append((match.start(), match.end(), word_op))
    # Symbol-Operatoren.
    for sym in _SYMBOL_OPS:
        idx = clause.find(sym)
        if idx > 0:
            candidates.append((idx, idx + len(sym), sym))
    if not candidates:
        raise ConversationFilterError(
            f"Keine gültige Bedingung in '{clause.strip()}' — erwartet 'feld OP wert'."
        )
    # Linkester Operator; bei Gleichstand der längere (deckt '>=' vs '>' ab).
    start, end, op = min(candidates, key=lambda c: (c[0], -(c[1] - c[0])))
    return clause[:start], op, clause[end:]


# ── Wert-/Operator-Builder pro Feld-Typ ───────────────────────────────────────


def _split_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _build_string(op: str, value: str, getter: Callable[[Conversation], list[str]]) -> Predicate:
    """Prädikat für Text-Felder (Prozess: 1 Wert; Status: Mehrwert)."""
    val = value.lower()
    if op in ("=", "=="):
        return lambda c: any(h.lower() == val for h in getter(c))
    if op == "!=":
        return lambda c: all(h.lower() != val for h in getter(c))
    if op in ("~", "contains"):
        return lambda c: any(val in h.lower() for h in getter(c))
    if op == "in":
        wanted = {v.lower() for v in _split_list(value)}
        return lambda c: any(h.lower() in wanted for h in getter(c))
    raise ConversationFilterError(f"Operator '{op}' ist für Text-Felder nicht erlaubt.")


def _build_process(op: str, value: str) -> Predicate:
    return _build_string(op, value, lambda c: [c.process_name])


def _build_status(op: str, value: str) -> Predicate:
    return _build_string(op, value, lambda c: list(c.statuses))


def _parse_network(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    net = parse_network_token(token)
    if net is None:
        raise ConversationFilterError(f"'{token}' ist keine gültige IP/CIDR.")
    return net


def _ip_in(ip: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def _build_ip(op: str, value: str) -> Predicate:
    if op in ("=", "=="):
        net = _parse_network(value)
        return lambda c: _ip_in(c.remote_ip, net)
    if op == "!=":
        net = _parse_network(value)
        return lambda c: not _ip_in(c.remote_ip, net)
    if op in ("~", "contains"):
        needle = value.lower()
        return lambda c: needle in c.remote_ip.lower()
    if op == "in":
        nets = [_parse_network(t) for t in _split_list(value)]
        return lambda c: any(_ip_in(c.remote_ip, n) for n in nets)
    raise ConversationFilterError(f"Operator '{op}' ist für 'ip' nicht erlaubt.")


def _parse_int(token: str) -> int:
    try:
        return int(token)
    except ValueError as exc:
        raise ConversationFilterError(f"'{token}' ist keine ganze Zahl.") from exc


_NUM_OPS: dict[str, Callable[[int, int], bool]] = {
    "=": lambda a, b: a == b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
}


def _build_numeric(
    op: str, value: str, getter: Callable[[Conversation], int]
) -> Predicate:
    """Generisches Zahlen-Prädikat (Vergleich/`in`) über einen Feld-Getter."""
    if op == "in":
        wanted = {_parse_int(t) for t in _split_list(value)}
        return lambda c: getter(c) in wanted
    cmp = _NUM_OPS.get(op)
    if cmp is None:
        raise ConversationFilterError(f"Operator '{op}' ist für Zahlen nicht erlaubt.")
    target = _parse_int(value)
    return lambda c: cmp(getter(c), target)


def _build_count(op: str, value: str) -> Predicate:
    return _build_numeric(op, value, lambda c: c.connection_count)


def _build_bytes(op: str, value: str) -> Predicate:
    # „bytes" = Gesamt (gesendet + empfangen) der Konversation.
    return _build_numeric(op, value, lambda c: c.bytes_sent + c.bytes_recv)


def _build_port(op: str, value: str) -> Predicate:
    # Mehrwertig: eine Konversation hat mehrere Ports → „existiert ein Port, der passt".
    if op == "in":
        wanted = {_parse_int(t) for t in _split_list(value)}
        return lambda c: any(p in wanted for p in c.ports)
    if op == "!=":
        target = _parse_int(value)
        return lambda c: target not in c.ports
    cmp = _NUM_OPS.get(op)
    if cmp is None:
        raise ConversationFilterError(f"Operator '{op}' ist für 'port' nicht erlaubt.")
    target = _parse_int(value)
    return lambda c: any(cmp(p, target) for p in c.ports)


def _parse_bool(token: str) -> bool:
    low = token.lower()
    if low in _TRUE_TOKENS:
        return True
    if low in _FALSE_TOKENS:
        return False
    raise ConversationFilterError(
        f"'{token}' ist kein Wahrheitswert (ja/nein)."
    )


def _build_bool(op: str, value: str) -> Predicate:
    target = _parse_bool(value)
    if op in ("=", "=="):
        return lambda c: c.suspicious == target
    if op == "!=":
        return lambda c: c.suspicious != target
    raise ConversationFilterError(
        f"Operator '{op}' ist für 'verdaechtig' nicht erlaubt (nur = / !=)."
    )


_BUILDERS: dict[str, Callable[[str, str], Predicate]] = {
    "process": _build_process,
    "status": _build_status,
    "ip": _build_ip,
    "count": _build_count,
    "bytes": _build_bytes,
    "port": _build_port,
    "bool": _build_bool,
}
