"""Tests für den deklarativen Konversations-Filter Phase 5).

Prüft Schnellfilter (Chips + Suche), den deklarativen Experten-Parser (alle Felder/
Operatoren, UND-Verknüpfung, IN/CIDR) und vor allem das Sicherheits-Verhalten:
ungültige/„böse" Ausdrücke enden in:class:`ConversationFilterError`, NIE in
Code-Ausführung (kein ``eval``/``exec``). Reine Logik — kein DB, keine GUI.
"""

from __future__ import annotations

import pytest

from tools.network_monitor.application import conversation_filter as cf
from tools.network_monitor.domain.exceptions import ConversationFilterError
from tools.network_monitor.domain.models import Conversation


def _conv(**kwargs) -> Conversation:
    base = {
        "process_name": "chrome.exe",
        "remote_ip": "8.8.8.8",
        "connection_count": 10,
        "ports": (443, 80),
        "statuses": ("ESTABLISHED",),
        "suspicious": False,
    }
    base.update(kwargs)
    return Conversation(**base)


@pytest.fixture
def convs() -> list[Conversation]:
    return [
        _conv(),
        _conv(
            process_name="evil.exe",
            remote_ip="9.9.9.9",
            suspicious=True,
            suspicious_reason="Feed",
            connection_count=99,
            ports=(4444,),
        ),
        _conv(
            process_name="svc.exe",
            remote_ip="10.0.0.5",
            ports=(22,),
            connection_count=3,
            statuses=("LISTEN",),
        ),
    ]


def _names(result: list[Conversation]) -> list[str]:
    return [c.process_name for c in result]


def _apply(expr: str, convs: list[Conversation]) -> list[str]:
    predicate = cf.parse_filter(expr)
    return _names([c for c in convs if predicate(c)])


def _apply_one(expr: str, conv: Conversation) -> bool:
    return cf.parse_filter(expr)(conv)


class TestExpertFilter:
    def test_leerer_ausdruck_matcht_alles(self, convs) -> None:
        assert _apply("", convs) == ["chrome.exe", "evil.exe", "svc.exe"]

    def test_prozess_contains(self, convs) -> None:
        assert _apply("prozess ~ chrome", convs) == ["chrome.exe"]

    def test_verdaechtig_bool(self, convs) -> None:
        assert _apply("verdaechtig = ja", convs) == ["evil.exe"]
        assert _apply("verdaechtig = nein", convs) == ["chrome.exe", "svc.exe"]

    def test_port_vergleich_mehrwertig(self, convs) -> None:
        assert _apply("port >= 1024", convs) == ["evil.exe"]
        assert _apply("port = 443", convs) == ["chrome.exe"]
        assert _apply("port in 22,80", convs) == ["chrome.exe", "svc.exe"]

    def test_ip_cidr_und_exakt(self, convs) -> None:
        assert _apply("ip in 10.0.0.0/8", convs) == ["svc.exe"]
        assert _apply("ip = 9.9.9.9", convs) == ["evil.exe"]

    def test_count_vergleich(self, convs) -> None:
        assert _apply("verbindungen > 50", convs) == ["evil.exe"]

    def test_bytes_total(self) -> None:
        # 'bytes' = gesendet + empfangen.
        big = _conv(process_name="dl", bytes_sent=600, bytes_recv=500)  # 1100
        small = _conv(process_name="idle", bytes_sent=10, bytes_recv=5)  # 15
        assert [c.process_name for c in (big, small) if cf.parse_filter("bytes > 1000")(c)] == ["dl"]
        assert [c.process_name for c in (big, small) if cf.parse_filter("bytes <= 100")(c)] == ["idle"]

    def test_status(self, convs) -> None:
        assert _apply("status = listen", convs) == ["svc.exe"]

    def test_und_verknuepfung(self, convs) -> None:
        assert _apply("prozess ~ e und verdaechtig = ja", convs) == ["evil.exe"]
        assert _apply("port = 443 und prozess ~ chrome", convs) == ["chrome.exe"]


class TestOperatorSplitEdgeCases:
    """Review C1/C2: linkester Operator gewinnt, Werte mit OP-Zeichen sind nutzbar."""

    def test_wert_mit_groesser_zeichen(self) -> None:
        # '~' steht links von '>' → als contains 'a>b' parsen (kein Fehler).
        c_match = _conv(process_name="a>b.exe")
        c_other = _conv(process_name="x.exe")
        pred = cf.parse_filter("prozess ~ a>b")
        assert pred(c_match) is True
        assert pred(c_other) is False

    def test_realer_operator_links_schlaegt_in_im_wert(self) -> None:
        # '=' links muss über ein späteres ' in ' im Wert gewinnen.
        c = _conv(process_name="win in tool")
        pred = cf.parse_filter("prozess = win in tool")
        assert pred(c) is True

    def test_groesser_gleich_vor_groesser(self) -> None:
        assert _apply_one("verbindungen >= 10", _conv(connection_count=10)) is True
        assert _apply_one("verbindungen >= 10", _conv(connection_count=9)) is False
        assert _apply_one("verbindungen > 10", _conv(connection_count=10)) is False


class TestFilterErrors:
    @pytest.mark.parametrize(
        "expr",
        [
            "unbekanntesfeld = x",
            "prozess",  # kein Operator
            "port = abc",  # keine Zahl
            "verdaechtig > 3",  # Operator für bool unzulässig + kein Wahrheitswert
            "ip = nonsense",  # keine IP/CIDR
            "verbindungen ~ 5",  # ~ für Zahl unzulässig
            "prozess = ",  # kein Wert
        ],
    )
    def test_ungueltig_wirft(self, expr: str) -> None:
        with pytest.raises(ConversationFilterError):
            cf.parse_filter(expr)

    def test_kein_eval_bei_code_artigem_ausdruck(self) -> None:
        # Ein eval-artiger Ausdruck darf NIE ausgeführt werden — er ist schlicht
        # kein gültiges Feld und endet als Fehler.
        with pytest.raises(ConversationFilterError):
            cf.parse_filter("__import__('os').system('echo pwned')")


class TestChips:
    def test_only_suspicious(self, convs) -> None:
        assert _names(cf.apply_chips(convs, only_suspicious=True)) == ["evil.exe"]

    def test_only_external(self, convs) -> None:
        # 10.0.0.5 ist privat → raus; 8.8.8.8 / 9.9.9.9 sind extern.
        assert _names(cf.apply_chips(convs, only_external=True)) == [
            "chrome.exe",
            "evil.exe",
        ]

    def test_search_substring(self, convs) -> None:
        assert _names(cf.apply_chips(convs, search="svc")) == ["svc.exe"]
        assert _names(cf.apply_chips(convs, search="9.9.9")) == ["evil.exe"]
        assert _names(cf.apply_chips(convs, search="listen")) == ["svc.exe"]

    def test_kombiniert(self, convs) -> None:
        assert _names(
            cf.apply_chips(convs, only_external=True, search="evil")
        ) == ["evil.exe"]


class TestIsExternalIp:
    def test_privat_und_lokal_nicht_extern(self) -> None:
        for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1"):
            assert cf.is_external_ip(ip) is False
        assert cf.is_external_ip("8.8.8.8") is True

    def test_muell_ip_nicht_extern(self) -> None:
        assert cf.is_external_ip("nicht-eine-ip") is False
