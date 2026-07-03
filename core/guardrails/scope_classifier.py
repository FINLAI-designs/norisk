"""
security_chat — Zusammenbau der Security-Chat-Schutzpipeline.

Stellt Factory-Funktionen bereit, die die guardrails-Bausteine mit dem
konkreten Ollama-Client verbinden — insbesondere den LLM-gestützten
Scope-Klassifikator (Layer 2). Bewusst getrennt von ``guardrails.py``, damit
die reinen Schutzschichten ohne Ollama-Abhängigkeit testbar bleiben.

Schichtzugehörigkeit: core/ — orchestriert Ports (IOllamaClient),
keine direkte Netzwerk-/GUI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
from collections.abc import Callable

from core.guardrails.guardrails import (
    DOMAIN_HANDBOOK,
    DOMAIN_OFFTOPIC,
    DOMAIN_SECURITY,
)
from core.guardrails.prompts import (
    SCOPE_CLASSIFIER_3WAY_SYSTEM_PROMPT,
    SCOPE_CLASSIFIER_SYSTEM_PROMPT,
    build_domain_classifier_user_message,
    build_scope_classifier_user_message,
)
from core.llm.ollama_client import IOllamaClient
from core.logger import get_logger

_log = get_logger(__name__)

#: Erkennt {"in_scope": true|false} auch in Ausgaben von "thinking"-Modellen,
#: die zusätzlichen Text (<think>…</think>) ausgeben.
_IN_SCOPE_RE = re.compile(r'"in_scope"\s*:\s*(true|false)', re.IGNORECASE)
_BARE_BOOL_RE = re.compile(r"\b(true|false)\b", re.IGNORECASE)

#: Alternation der gültigen Domänen (an die Konstanten gebunden, kein Drift).
_DOMAIN_ALT = "|".join(
    re.escape(d) for d in (DOMAIN_HANDBOOK, DOMAIN_SECURITY, DOMAIN_OFFTOPIC)
)
#: Erkennt {"domain": "handbook|security|offtopic"} (auch mit Think-Text).
_DOMAIN_RE = re.compile(rf'"domain"\s*:\s*"({_DOMAIN_ALT})"', re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(rf"\b({_DOMAIN_ALT})\b", re.IGNORECASE)

#: Klassifikator-Temperatur: 0 für deterministische Entscheidungen.
_CLASSIFIER_TEMPERATURE = 0.0


def parse_in_scope(raw_output: str, *, default: bool = True) -> bool:
    """Parst die JSON-Entscheidung des Scope-Klassifikators robust.

    Args:
        raw_output: Roh-Ausgabe des Klassifikator-Modells (kann Think-Text
            enthalten).
        default: Rückgabewert, wenn keine Entscheidung erkennbar ist. Default
            ``True`` (fail-open auf den strikten System-Prompt als
            nachgelagerte Schicht, statt legitime Fragen über-zu-blocken).

    Returns:
        True, wenn das Modell die Anfrage als IT-Security einstuft.
    """
    if not raw_output:
        return default
    match = _IN_SCOPE_RE.search(raw_output)
    if match:
        return match.group(1).lower() == "true"
    # Fallback: letzte nackte Bool-Angabe in der Ausgabe.
    bare = _BARE_BOOL_RE.findall(raw_output)
    if bare:
        return bare[-1].lower() == "true"
    _log.warning("Scope-Klassifikator-Ausgabe nicht interpretierbar — Default.")
    return default


def make_ollama_scope_classifier(
    client: IOllamaClient, model: str
) -> Callable[[str], bool]:
    """Erzeugt einen LLM-Scope-Klassifikator gebunden an Client + Modell.

    Args:
        client: Ollama-Client (Port).
        model: Zu verwendender Modellname (bereits aufgelöst).

    Returns:
        Funktion ``classify(text) -> bool``, die True liefert, wenn der Text
        eine IT-Security-Anfrage ist. Wirft die Client-Exceptions weiter; der
        ScopeGate fängt sie ab und nutzt dann seine Heuristik.
    """

    def classify(text: str) -> bool:
        user_message = build_scope_classifier_user_message(text)
        output = client.chat(
            model=model,
            messages=[{"role": "user", "content": user_message}],
            on_token=lambda _t: None,
            system_prompt=SCOPE_CLASSIFIER_SYSTEM_PROMPT,
            temperature=_CLASSIFIER_TEMPERATURE,
        )
        return parse_in_scope(output)

    return classify


def parse_scope_domain(raw_output: str, *, default: str = DOMAIN_HANDBOOK) -> str:
    """Parst die 3-wertige Domänen-Entscheidung des Klassifikators robust.

    Args:
        raw_output: Roh-Ausgabe des Klassifikator-Modells (kann Think-Text
            enthalten).
        default: Domäne, wenn keine Entscheidung erkennbar ist. Default
            ``DOMAIN_HANDBOOK`` — bei unklarer Ausgabe lieber eine
            Bedienungsantwort versuchen als fälschlich abzulehnen (Off-Topic
            muss explizit erkannt werden). Der Handbuch-Pfad leakt keine
            internen Inhalte (Denyliste + strenger Output-Filter).

    Returns:
        Eine der Domänen ``handbook`` / ``security`` / ``offtopic``.
    """
    if not raw_output:
        return default
    match = _DOMAIN_RE.search(raw_output)
    if match:
        return match.group(1).lower()
    bare = _BARE_DOMAIN_RE.findall(raw_output)
    if bare:
        return bare[-1].lower()
    _log.warning("3-wertige Scope-Ausgabe nicht interpretierbar — Default-Domäne.")
    return default


def make_ollama_domain_classifier(
    client: IOllamaClient, model: str
) -> Callable[[str], str]:
    """Erzeugt einen 3-wertigen LLM-Domänen-Klassifikator.

    Args:
        client: Ollama-Client (Port).
        model: Zu verwendender Modellname (bereits aufgelöst).

    Returns:
        Funktion ``classify(text) -> str``, die ``handbook``/``security``/
        ``offtopic`` liefert. Wirft die Client-Exceptions weiter; der ScopeGate
        fängt sie ab und nutzt dann seine Heuristik.
    """

    def classify(text: str) -> str:
        user_message = build_domain_classifier_user_message(text)
        output = client.chat(
            model=model,
            messages=[{"role": "user", "content": user_message}],
            on_token=lambda _t: None,
            system_prompt=SCOPE_CLASSIFIER_3WAY_SYSTEM_PROMPT,
            temperature=_CLASSIFIER_TEMPERATURE,
        )
        return parse_scope_domain(output)

    return classify
