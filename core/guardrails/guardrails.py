"""
guardrails — Deterministische Schutzschichten für den NoRisk Security-Chat.

Stellt die Defense-in-Depth-Bausteine bereit, die der ChatService um den
reinen Ollama-Aufruf legt (siehe Plan, Zielarchitektur):

  * detect_injection_signals — weiche Heuristik (Layer 3): erkennt
        typische Prompt-Injection-Muster für Logging/Audit. Blockt NICHT
        hart, da umgehbar (OWASP LLM01 #3); dient der Nachvollziehbarkeit.
  * ScopeGate — Themen-Gate (Layer 2): lässt nur
        IT-Security-Anfragen durch, lehnt Off-Topic mit Standard-Refusal ab.
        Der LLM-Klassifikator wird als Callable injiziert (Testbarkeit,
        Schicht-Trennung — guardrails ruft Ollama nicht selbst auf).
  * filter_security_output — Output-Validierung (Layer 7): redigiert
        ausschließlich ECHTE Secrets. WICHTIG: anders als der Handbuch-Filter
        werden legitime Security-Inhalte (IOC-Hashes, Base64-Zertifikate,
        JWT-Beispiele) NICHT geschwärzt — sonst wäre der Filter im
        Security-Kontext schädlich (Vollständigkeitskritik 4.7).

Schichtzugehörigkeit: core/ — kein PySide6, keine direkten I/O-Ops.
Aus tools/ki_integration/application/ nach core/guardrails/ gehoben.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from core.logger import get_logger

_log = get_logger(__name__)

_REDACTED = "[ENTFERNT — Geheimnis]"

# ---------------------------------------------------------------------------
# Scope-Domänen des vereinten FINLAI-Assistenten, 3-wertig)
# ---------------------------------------------------------------------------
#: Bedienungs-/Handbuch-Anfragen (Anwenderhandbuch-RAG, strenger Output-Filter).
DOMAIN_HANDBOOK: str = "handbook"
#: IT-Sicherheits-Anfragen (Security-Korpus-RAG, IOC-erhaltender Output-Filter).
DOMAIN_SECURITY: str = "security"
#: Themenfremd — wird ohne Modellaufruf abgelehnt.
DOMAIN_OFFTOPIC: str = "offtopic"
#: Erlaubte Domänen-Werte (Validierung der Klassifikator-Ausgabe).
_VALID_DOMAINS: frozenset[str] = frozenset(
    {DOMAIN_HANDBOOK, DOMAIN_SECURITY, DOMAIN_OFFTOPIC}
)

# ---------------------------------------------------------------------------
# Layer 7 — Output-Filter (nur ECHTE Secrets, KEINE Security-Inhalte)
# ---------------------------------------------------------------------------
# Bewusst KEIN breites Base64-Pattern ([A-Za-z0-9+/]{32,}) — das würde
# IOC-Hashes, Zertifikate und JWT-Beispiele zerstören, die ein
# Security-Assistent legitim ausgibt.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # OpenAI-/Anthropic-artige API-Keys (echte Token, kein Beispiel-Hash).
    ("api_token", re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_\-]{20,}\b")),
    # Explizite Zuweisung eines Geheimnis-Werts (Schlüssel = Wert).
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|passwort|password|token|bearer)\b"
            r"\s*[:=]\s*['\"]?[^\s'\"]{6,}",
        ),
    ),
)


#: Pflicht-Disclaimer für CVE-/Schwachstellen-Aussagen (deterministisch
#: erzwungen, siehe ensure_cve_disclaimer). Red-Team-Befund T6: ein rein
#: prompt-basierter Disclaimer ist unter "antworte nur mit einem Wort"
#: umgehbar — OWASP LLM01 empfiehlt Durchsetzung per deterministischem Code.
CVE_DISCLAIMER_LINE: str = (
    "\n\n> Hinweis: Diese Sicherheitsinformation kann veraltet sein. Bitte "
    "prüfen Sie den aktuellen Stand bei einer offiziellen Quelle "
    "(z. B. https://nvd.nist.gov/ oder https://www.bsi.bund.de/)."
)

_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_DISCLAIMER_MARKERS = ("nvd.nist.gov", "bsi.bund.de", "veraltet", "offiziellen quelle")


def _has_cve_disclaimer(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _DISCLAIMER_MARKERS)


def ensure_cve_disclaimer(user_text: str, response: str) -> str:
    """Erzwingt den CVE-Veraltetheits-Hinweis deterministisch.

    Greift, wenn im Gespräch eine konkrete CVE-ID vorkommt (in der Frage ODER
    der Antwort) und die Antwort noch keinen Quellen-/Veraltetheits-Hinweis
    enthält. Schließt den Red-Team-Befund T6 (Disclaimer-Bypass via
    Kürze-Vorgabe), unabhängig vom Modellverhalten.

    Args:
        user_text: Die (rohe) Nutzer-Eingabe.
        response: Die (bereits gefilterte) Modell-Antwort.

    Returns:
        Die Antwort, ggf. mit angehängtem Pflicht-Disclaimer.
    """
    if not response:
        return response
    combined = f"{user_text}\n{response}"
    if _CVE_ID_RE.search(combined) and not _has_cve_disclaimer(response):
        return response.rstrip() + CVE_DISCLAIMER_LINE
    return response


def filter_security_output(text: str) -> tuple[str, list[str]]:
    """Redigiert echte Geheimnisse aus der LLM-Antwort (Layer 7).

    Im Gegensatz zum Handbuch-Filter werden legitime Security-Inhalte
    (Hash-IOCs, Base64-Zertifikate, JWT-Beispiele) bewusst NICHT geschwärzt.

    Args:
        text: Rohe LLM-Antwort.

    Returns:
        Tuple aus bereinigtem Text und Liste der ausgelösten Filter-Labels
        (z. B. ``["private_key"]``). Leere Liste, wenn nichts redigiert wurde.
    """
    if not text:
        return text, []

    triggered: list[str] = []
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(_REDACTED, text)
            triggered.append(label)
    return text, triggered


# Handbuch-Variante (Layer 7, STRENGER): Der Handbuch-Assistent erklärt die
# Bedienung und darf — anders als der Security-Assistent — NIEMALS IOC-Hashes,
# Zertifikate, JWTs oder andere lange Base64-Blobs ausgeben. Daher zusätzlich
# breites Base64 (>=32) und PRAGMA key zu den echten Secret-Mustern.
_HANDBUCH_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    *_SECRET_PATTERNS,
    ("pragma_key", re.compile(r"(?i)PRAGMA\s+key")),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")),
)


def filter_handbuch_output(text: str) -> tuple[str, list[str]]:
    """Redigiert Geheimnisse aus einer Handbuch-Antwort (Layer 7, streng).

    Strenger als:func:`filter_security_output`: Der Handbuch-Assistent darf
    keine IOC-Hashes, Zertifikate oder JWT-Beispiele ausgeben, daher wird auch
    breites Base64 (>=32 Zeichen) und ``PRAGMA key`` redigiert. Dieser Filter
    darf NIEMALS auf Security-Antworten angewandt werden (würde legitime
    Lehrinhalte zerstören — siehe Plan B-5).

    Args:
        text: Rohe LLM-Antwort des Handbuch-Pfads.

    Returns:
        Tuple aus bereinigtem Text und Liste der ausgelösten Filter-Labels.
        Leere Liste, wenn nichts redigiert wurde.
    """
    if not text:
        return text, []

    triggered: list[str] = []
    for label, pattern in _HANDBUCH_SECRET_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(_REDACTED, text)
            triggered.append(label)
    return text, triggered


# ---------------------------------------------------------------------------
# Layer 3 — Injection-Heuristik (weich, nur Signale/Logging)
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous",
        re.compile(
            r"(?i)(ignor\w*|missacht\w*|vergiss|disregard|forget)\b.{0,40}"
            r"\b(previous|above|prior|all|alle|vorherig\w*|bisherig\w*|"
            r"anweisung\w*|instruction\w*|regeln|rules|vorgaben|prompt)",
        ),
    ),
    (
        "role_override",
        re.compile(
            r"(?i)\b(du bist (jetzt|ab sofort)|you are now|act as|"
            r"agiere als|verhalte dich wie|pretend|developer mode|"
            r"entwicklermodus|jailbreak|\bdan\b|do anything now)\b",
        ),
    ),
    (
        "system_prompt_leak",
        re.compile(
            r"(?i)(system[\s-]?prompt|systemprompt|deine (anweisungen|regeln|"
            r"vorgaben)|initial instructions|repeat the (words|text) above|"
            r"gib .{0,20}(anweisungen|prompt) (aus|preis|wieder))",
        ),
    ),
    ("long_base64", re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")),
    (
        "fake_qa_structure",
        re.compile(r"(?is)(^|\n)\s*(user|assistant|nutzer|assistent)\s*:"),
    ),
)


def detect_injection_signals(raw_text: str) -> list[str]:
    """Erkennt typische Prompt-Injection-Muster (Layer 3, weich).

    Diese Heuristik blockt NICHT — sie liefert Signale für Logging/Audit
    und ist bewusst umgehbar (semantische Varianten, GCG-Suffixe). Sie wird
    auf der ROH-Eingabe (vor der Normalisierung) aufgerufen, um auch
    Verschleierungsversuche zu erfassen.

    Args:
        raw_text: Unveränderte Nutzer-Eingabe (vor Normalisierung).

    Returns:
        Liste erkannter Signal-Namen (z. B. ``["ignore_previous"]``).
        Leere Liste, wenn keine Muster gefunden wurden.
    """
    if not raw_text:
        return []

    signals: list[str] = []

    # Versteckte/unsichtbare Zeichen (Smuggling-Träger): Format-/Steuerzeichen
    # (außer Whitespace) und der Unicode-Tag-Block.
    if any(
        ("\U000e0000" <= ch <= "\U000e007f")
        or (ch not in ("\n", "\t", "\r") and unicodedata.category(ch) in ("Cf", "Cc"))
        for ch in raw_text
    ):
        signals.append("hidden_chars")

    # Gemischte Schrift (Homoglyph-Spoofing): lateinische Buchstaben plus
    # kyrillische/griechische Zeichen im selben Text.
    has_latin = any("a" <= ch.lower() <= "z" for ch in raw_text)
    has_confusable_script = any(
        (0x0400 <= ord(ch) <= 0x04FF) or (0x0370 <= ord(ch) <= 0x03FF)
        for ch in raw_text
    )
    if has_latin and has_confusable_script:
        signals.append("mixed_script")

    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(raw_text):
            signals.append(label)

    return signals


# ---------------------------------------------------------------------------
# Layer 2 — Scope-Gate (nur IT-Security)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScopeVerdict:
    """Ergebnis der Scope-Prüfung.

    Attributes:
        in_scope: True, wenn die Anfrage bearbeitet werden darf (nicht
            Off-Topic). Äquivalent zu ``domain != DOMAIN_OFFTOPIC``.
        method: Wie entschieden wurde — ``"llm"``, ``"heuristic"`` oder
            ``"default"`` (Fallback bei Unsicherheit ohne Klassifikator).
        reason: Kurze Begründung (für Audit/Logging, keine Inhalte).
        domain: Ziel-Domäne, 3-wertig) — ``DOMAIN_HANDBOOK``,
            ``DOMAIN_SECURITY`` oder ``DOMAIN_OFFTOPIC``. Steuert im vereinten
            Assistenten das Prompt-/Retriever-/Output-Filter-Routing. Default
            ``DOMAIN_SECURITY`` für Abwärtskompatibilität mit dem binären
            Security-Chat (in_scope=True bedeutete dort „IT-Security").
    """

    in_scope: bool
    method: str
    reason: str
    domain: str = DOMAIN_SECURITY


# Eindeutig themenfremde Marker (Fast-Path nur, wenn KEIN Security-Bezug).
_OFFTOPIC_MARKERS: tuple[str, ...] = (
    "rezept",
    "kochen",
    "backen",
    "gedicht",
    "witz",
    "reise",
    "urlaub",
    "wetter",
    "fußball",
    "fussball",
    "recipe",
    "cooking",
    "poem",
    "joke",
    "travel",
    "horoscope",
    "horoskop",
)

# Starke Security-Marker (Fast-Path-Hinweis; alleine NICHT ausreichend,
# weil Off-Topic-Tarnung Security-Begriffe missbrauchen kann).
_SECURITY_MARKERS: tuple[str, ...] = (
    "cve",
    "schwachstelle",
    "vulnerab",
    "exploit",
    "phishing",
    "malware",
    "ransomware",
    "firewall",
    "verschlüssel",
    "encryption",
    "zertifikat",
    "certificate",
    "tls",
    "patch",
    "härtung",
    "hardening",
    "angriff",
    "attack",
    "passwort",
    "password",
    "authentifiz",
    "bsi",
    "owasp",
    # Bewertung/Einordnung der eigenen Ergebnisse: Score-/Audit-Fragen
    # sind IT-Sicherheit und sollen NICHT als off-topic abgelehnt werden.
    "score",
    "audit",
    "nis2",
    "risikostufe",
)

# Starke Bedienungs-/Handbuch-Marker (Fast-Path-Hinweis). Nur
# Heuristik-Fallback, wenn der LLM-Klassifikator ausfällt; Security-Marker
# haben Vorrang (konservativere Behandlung im Zweifel).
_HANDBOOK_MARKERS: tuple[str, ...] = (
    "installier",
    "deinstallier",
    "öffne",
    "öffnen",
    "schaltfläche",
    "menü",
    "einstellung",
    "konfigurier",
    "exportier",
    "importier",
    "speicher",
    "anmeld",
    "abmeld",
    "login",
    "lizenz",
    "aktivier",
    "update",
    "aktualisier",
    "fenster",
    "reiter",
    "dashboard",
    "bedien",
    "wie finde ich",
    "wo finde ich",
    "wie kann ich",
    "wizard",
    "bericht",
    "drucken",
)


class ScopeGate:
    """Themen-Gate (Layer 2): klassifiziert die Ziel-Domäne einer Anfrage.

    Maßgeblich ist der injizierte LLM-Klassifikator (Schicht-Trennung +
    Testbarkeit). Fällt er aus oder fehlt er, greift eine konservative
    Heuristik.

    Zwei Betriebsmodi:
      * **Binär (Legacy, Security-Chat):** ``classify_fn`` liefert True/False
        für „ist IT-Security". Wird intern auf die Domänen-Schnittstelle
        adaptiert (True→``security``, False→``offtopic``), damit ``check``
        nur EINEN Klassifikator-Pfad kennt. ``in_scope``/``method`` bleiben
        abwärtskompatibel.
      * **3-wertig (vereinter Assistent):** ``domain_classify_fn`` liefert
        direkt ``handbook``/``security``/``offtopic``.

    Args:
        classify_fn: Binärer Klassifikator (Legacy). Wird ignoriert, wenn
            ``domain_classify_fn`` gesetzt ist. ``None`` = nur Heuristik.
        domain_classify_fn: 3-wertiger Domänen-Klassifikator (bevorzugt).
        default_domain: Domäne bei Unsicherheit/ungültiger Ausgabe. Für den
            Legacy-Security-Chat ``DOMAIN_SECURITY`` (durchlassen, strikter
            System-Prompt als Backstop); der vereinte Assistent setzt
            ``DOMAIN_HANDBOOK`` (Bedienungsfragen nicht fälschlich blocken).
    """

    def __init__(
        self,
        classify_fn: Callable[[str], bool] | None = None,
        *,
        domain_classify_fn: Callable[[str], str] | None = None,
        default_domain: str = DOMAIN_SECURITY,
    ) -> None:
        self._default_domain = default_domain
        if domain_classify_fn is not None:
            self._domain_fn: Callable[[str], str] | None = domain_classify_fn
        elif classify_fn is not None:

            def _adapt(text: str) -> str:
                return DOMAIN_SECURITY if classify_fn(text) else DOMAIN_OFFTOPIC

            self._domain_fn = _adapt
        else:
            self._domain_fn = None

    def check(self, text: str) -> ScopeVerdict:
        """Klassifiziert die Ziel-Domäne von ``text``.

        Args:
            text: Bereits normalisierte Nutzer-Eingabe.

        Returns:
            ScopeVerdict mit Domäne, in_scope-Flag, Methode und Begründung.
        """
        stripped = (text or "").strip()
        if not stripped:
            return ScopeVerdict(False, "heuristic", "leer", DOMAIN_OFFTOPIC)

        # LLM-Klassifikator ist maßgeblich (erkennt getarnte Off-Topic-Fälle).
        if self._domain_fn is not None:
            try:
                domain = self._domain_fn(stripped)
                if domain not in _VALID_DOMAINS:
                    _log.warning(
                        "Scope-Klassifikator lieferte ungültige Domäne — Default."
                    )
                    domain = self._default_domain
                in_scope = domain != DOMAIN_OFFTOPIC
                reason = "klassifikator" if in_scope else "off_topic"
                return ScopeVerdict(in_scope, "llm", reason, domain)
            except Exception as exc:  # noqa: BLE001 — Fallback auf Heuristik
                _log.warning(
                    "Scope-Klassifikator fehlgeschlagen, nutze Heuristik: %s",
                    type(exc).__name__,
                )

        return self._heuristic(stripped)

    def _heuristic(self, text: str) -> ScopeVerdict:
        """Konservativer 3-wertiger Fallback ohne LLM (degradierter Modus).

        Security-Marker haben Vorrang (im Zweifel strengere Behandlung), dann
        Handbuch-Marker, dann Off-Topic-Marker. Bleibt alles unklar, fällt die
        Entscheidung auf ``self._default_domain``.
        """
        low = text.lower()
        if any(m in low for m in _SECURITY_MARKERS):
            return ScopeVerdict(True, "heuristic", "security_marker", DOMAIN_SECURITY)
        if any(m in low for m in _HANDBOOK_MARKERS):
            return ScopeVerdict(True, "heuristic", "handbook_marker", DOMAIN_HANDBOOK)
        if any(m in low for m in _OFFTOPIC_MARKERS):
            return ScopeVerdict(False, "heuristic", "offtopic_marker", DOMAIN_OFFTOPIC)
        # Unsicher: auf die konfigurierte Default-Domäne fallen — der strikte
        # System-Prompt ist die nachgelagerte Schicht (Defense-in-Depth).
        return ScopeVerdict(
            self._default_domain != DOMAIN_OFFTOPIC,
            "default",
            "unsicher_systemprompt_backstop",
            self._default_domain,
        )
